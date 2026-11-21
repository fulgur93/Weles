using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Weles.Agent.Communication;
using Weles.Agent.Configuration;
using Weles.Agent.Workers;
using Weles.App.Hosting;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Models;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Agents;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Platform;
using Weles.Infrastructure.Risk;
using Weles.Infrastructure.Scanning;
using Weles.Infrastructure.Settings;
using Weles.Infrastructure.Vulnerabilities;
using Weles.Tests.Support;

namespace Weles.Tests.Agents;

public class AgentTests
{
    private const string Remote = "10.0.0.50";

    private sealed class Env : IAsyncDisposable
    {
        public required TestDatabase Db { get; init; }
        public required AgentService Agents { get; init; }
        public required ScanCoordinator Coordinator { get; init; }
        public required ScanTargetService Targets { get; init; }

        public async Task<int> ScopeAsync(string name, string entries, bool approve = true)
        {
            var created = await Targets.CreateAsync(new ScanTargetInput(name, null, entries, null, false));
            Assert.True(created.Success, string.Join(" ", created.Errors));
            if (approve) Assert.True((await Targets.ApproveAsync(created.Id!.Value, confirmedAuthorization: true)).Success);
            return created.Id!.Value;
        }

        public async Task<(Weles.Core.Entities.Agent Agent, string Token)> EnrolledAsync(params int[] scopes)
        {
            var (enrollment, error) = await Agents.CreateAsync("Biuro " + Guid.NewGuid().ToString("N")[..6], scopes);
            Assert.Null(error);
            var enrolled = await Agents.EnrollAsync(new EnrollRequest(enrollment!.Code, System()), Remote);
            Assert.Equal(200, enrolled.StatusCode);
            var (agent, status) = await Agents.AuthenticateAsync(enrolled.Body!.Token, Remote);
            Assert.Equal(200, status);
            return (agent!, enrolled.Body.Token);
        }

        public ValueTask DisposeAsync() => Db.DisposeAsync();
    }

    private static AgentSystemInfo System() => new("biuro-pc", "Linux test", "X64", "1.0", 4,
        [new AgentInterface("eth0", "Ethernet", "10.0.0.50", 24, "10.0.0.0/24", "10.0.0.1", "aa:bb:cc:00:00:50")]);

    private static async Task<Env> SetupAsync(ScanOptions? options = null)
    {
        var db = await TestDatabase.CreateAsync();
        var coordinator = new ScanCoordinator(TimeProvider.System);
        var writer = new ScanResultWriter(db, TimeProvider.System);
        var settings = new SettingsService(db, TimeProvider.System);
        var post = new ScanPostProcessor(new Weles.Infrastructure.Fingerprint.SignatureService(db, TimeProvider.System, NullLogger<Weles.Infrastructure.Fingerprint.SignatureService>.Instance), new VulnerabilityMatchingService(db, TimeProvider.System, NullLogger<VulnerabilityMatchingService>.Instance),
            new RiskAssessmentService(db, settings, TimeProvider.System, NullLogger<RiskAssessmentService>.Instance), db, TimeProvider.System, NullLogger<ScanPostProcessor>.Instance);
        var opts = Options.Create(options ?? new ScanOptions());
        return new Env
        {
            Db = db, Coordinator = coordinator,
            Agents = new AgentService(db, writer, coordinator, post, new OuiDatabase(), opts, TimeProvider.System, NullLogger<AgentService>.Instance),
            Targets = new ScanTargetService(db, coordinator, opts, TimeProvider.System, NullLogger<ScanTargetService>.Instance)
        };
    }

    private static AgentHost Host(string ip, params int[] ports) => new(ip, DiscoveryMethod.TcpConnect, 1.5, 64, "host-" + ip, "aa:bb:cc:00:00:99", false,
        new HostClassification(AssetType.LinuxHost, "Linux", 60, ["test"]),
        ports.Select(p => new PortScanResult(p, "syn-ack", new ServiceProbeResult(new ServiceIdentification
            { ServiceName = "ssh", Product = "OpenSSH", Version = "8.9p1", Method = "banner", Confidence = 95, Banner = "SSH-2.0-OpenSSH_8.9p1" }, null))).ToList(),
        null, false);

    private static AgentScanState State(int targeted) => new(targeted, targeted, 100, "aa:bb:cc:00:00:01", [new SegmentInfo("10.0.0.0/24", "10.0.0.1", "aa:bb:cc:00:00:01", null)]);

    [Fact]
    public async Task Enrollment_codes_and_tokens_work_once_and_only_while_valid()
    {
        await using var env = await SetupAsync();
        var lan = await env.ScopeAsync("Biuro", "10.0.0.0/24");
        var external = await env.ScopeAsync("Domena", "example.org", approve: false);

        // Only local scopes without names can be given to an agent.
        Assert.NotNull((await env.Agents.CreateAsync("A", [external])).Error);
        var (enrollment, error) = await env.Agents.CreateAsync("A", [lan]);
        Assert.Null(error);
        Assert.Equal(AgentStatus.Pending, enrollment!.Agent.Status);
        Assert.NotNull((await env.Agents.CreateAsync("A", [])).Error); // name taken

        Assert.Equal(401, (await env.Agents.EnrollAsync(new EnrollRequest("wrong-code", System()), Remote)).StatusCode);
        var enrolled = await env.Agents.EnrollAsync(new EnrollRequest(enrollment.Code, System()), Remote);
        Assert.Equal(200, enrolled.StatusCode);
        // One-time: the same code does not enroll a second agent.
        Assert.Equal(401, (await env.Agents.EnrollAsync(new EnrollRequest(enrollment.Code, System()), "10.0.0.51")).StatusCode);

        var token = enrolled.Body!.Token;
        Assert.True(token.Length >= 40);
        await using (var db = env.Db.CreateDbContext())
        {
            var stored = await db.Agents.SingleAsync();
            Assert.NotEqual(token, stored.TokenHash);            // only a hash is stored
            Assert.Equal(AgentService.Hash(token), stored.TokenHash);
            Assert.Null(stored.EnrollmentCodeHash);
            Assert.Equal("biuro-pc", stored.Hostname);
        }

        Assert.Equal(200, (await env.Agents.AuthenticateAsync(token, Remote)).Status);
        Assert.True(await env.Agents.RevokeAsync(enrolled.Body.AgentId));
        Assert.Equal(401, (await env.Agents.AuthenticateAsync(token, Remote)).Status);

        // An expired code is refused.
        var (late, _) = await env.Agents.CreateAsync("B", [lan]);
        await using (var db = env.Db.CreateDbContext())
        {
            await db.Agents.Where(a => a.Id == late!.Agent.Id).ExecuteUpdateAsync(u => u.SetProperty(a => a.EnrollmentExpiresAt, DateTime.UtcNow.AddMinutes(-1)));
        }

        Assert.Equal(401, (await env.Agents.EnrollAsync(new EnrollRequest(late!.Code, System()), Remote)).StatusCode);
    }

    [Fact]
    public async Task Repeated_failures_from_one_address_are_throttled()
    {
        await using var env = await SetupAsync();
        for (var i = 0; i < 10; i++) Assert.Equal(401, (await env.Agents.AuthenticateAsync("bad-token-" + i, "10.9.9.9")).Status);
        Assert.Equal(429, (await env.Agents.AuthenticateAsync("bad-token", "10.9.9.9")).Status);
        Assert.Equal(429, (await env.Agents.EnrollAsync(new EnrollRequest("x", System()), "10.9.9.9")).StatusCode);
        Assert.Equal(401, (await env.Agents.AuthenticateAsync("bad-token", "10.9.9.10")).Status); // another address is not affected
    }

    [Fact]
    public async Task An_agent_scans_only_its_approved_scopes_and_cannot_send_foreign_results()
    {
        await using var env = await SetupAsync();
        var lan = await env.ScopeAsync("Biuro", "10.0.0.0/24");
        var unassigned = await env.ScopeAsync("Inny", "10.1.0.0/24");
        var (agent, _) = await env.EnrolledAsync(lan);

        Assert.False((await env.Agents.StartScanAsync(agent.Id, unassigned, "quick")).Success);
        var start = await env.Agents.StartScanAsync(agent.Id, lan, "quick");
        Assert.True(start.Success, string.Join(" ", start.Errors));
        Assert.False((await env.Agents.StartScanAsync(agent.Id, lan, "quick")).Success); // one at a time
        Assert.Contains(env.Coordinator.ActiveScans(), p => p.ScanId == start.Id);

        var beat = await env.Agents.HeartbeatAsync(agent, new HeartbeatRequest(System(), null), Remote);
        var job = beat.Body!.Job!;
        Assert.Equal(start.Id, job.ScanId);
        Assert.Equal([new ScopeEntry("10.0.0.0/24", false)], job.Entries);

        // Another agent cannot touch this scan.
        var (other, _) = await env.EnrolledAsync(lan);
        Assert.Equal(404, (await env.Agents.ResultsAsync(other, job.ScanId, new ResultsRequest([Host("10.0.0.7", 22)], [], State(254)), Remote)).StatusCode);

        var bad = Host("10.0.0.8", 0);
        var hugeName = Host("10.0.0.9", 22) with { Hostname = new string('x', 5000) };
        var upload = await env.Agents.ResultsAsync(agent, job.ScanId, new ResultsRequest(
            [Host("10.0.0.7", 22), Host("10.0.0.7", 22), Host("192.168.5.5", 22), Host("8.8.8.8", 53), bad, hugeName],
            [new AgentEvent(ScanEventLevel.Info, "agent\u0001 event")], State(254)), Remote);
        Assert.Equal(200, upload.StatusCode);
        Assert.Equal(2, upload.Body!.Accepted);   // 10.0.0.7 once and 10.0.0.9
        Assert.Equal(4, upload.Body.Rejected);    // duplicate, outside scope ×2, invalid port
        Assert.False(upload.Body.Cancel);

        // The user stops the scan – the agent learns it from its next call.
        env.Coordinator.RequestStop(job.ScanId);
        Assert.True((await env.Agents.ResultsAsync(agent, job.ScanId, new ResultsRequest([], [], State(254)), Remote)).Body!.Cancel);
        Assert.True((await env.Agents.HeartbeatAsync(agent, new HeartbeatRequest(System(), job.ScanId), Remote)).Body!.CancelRunning);

        var done = await env.Agents.CompleteAsync(agent, job.ScanId, new CompleteRequest(ScanStatus.Cancelled, null, [], State(254)), Remote);
        Assert.Equal(200, done.StatusCode);
        await using var db = env.Db.CreateDbContext();
        var scan = await db.Scans.SingleAsync(s => s.Id == job.ScanId);
        Assert.Equal(ScanStatus.Cancelled, scan.Status);
        Assert.Equal(ScanTrigger.Agent, scan.Trigger);
        Assert.Equal(2, scan.HostsAlive);
        Assert.Equal("aa:bb:cc:00:00:01", scan.NetworkFingerprint);
        var hosts = await db.DiscoveredHosts.Where(h => h.ScanId == job.ScanId).ToListAsync();
        Assert.All(hosts, h => Assert.True(h.DiscoveryMethods.HasFlag(DiscoveryMethod.Agent)));
        Assert.Equal(255, hosts.Single(h => h.IpAddress == "10.0.0.9").Hostname!.Length);
        Assert.DoesNotContain(await db.ScanEvents.Where(e => e.ScanId == job.ScanId).Select(e => e.Message).ToListAsync(), m => m.Contains('\u0001'));
        Assert.True(await db.RiskScores.AnyAsync(r => r.ScanId == job.ScanId)); // matching and risk ran after the scan
        Assert.False(env.Coordinator.IsActive(job.ScanId));
    }

    [Fact]
    public async Task Revocation_and_a_restarted_agent_end_its_scans()
    {
        await using var env = await SetupAsync();
        var lan = await env.ScopeAsync("Biuro", "10.0.0.0/24");
        var (agent, _) = await env.EnrolledAsync(lan);

        var first = (await env.Agents.StartScanAsync(agent.Id, lan, "quick")).Id!.Value;
        Assert.NotNull((await env.Agents.HeartbeatAsync(agent, new HeartbeatRequest(System(), null), Remote)).Body!.Job);
        // The agent restarted and calls as idle – the scan it was running is marked failed, results kept.
        Assert.Null((await env.Agents.HeartbeatAsync(agent, new HeartbeatRequest(System(), null), Remote)).Body!.Job);

        var second = (await env.Agents.StartScanAsync(agent.Id, lan, "quick")).Id!.Value;
        Assert.True(await env.Agents.RevokeAsync(agent.Id));
        await using var db = env.Db.CreateDbContext();
        Assert.Equal(ScanStatus.Failed, (await db.Scans.SingleAsync(s => s.Id == first)).Status);
        Assert.Equal(ScanStatus.Cancelled, (await db.Scans.SingleAsync(s => s.Id == second)).Status);
        Assert.False(await env.Agents.DeleteAsync(9999));
        Assert.True(await env.Agents.DeleteAsync(agent.Id));
        await using var after = env.Db.CreateDbContext();
        Assert.Null((await after.Scans.SingleAsync(s => s.Id == first)).AgentId); // history stays, without the deleted agent
    }

    [Fact]
    public void Listener_settings_refuse_all_interfaces_and_public_addresses()
    {
        Assert.Null(new AgentListenerSettings(true, "192.168.0.10", 7443).Validate());
        Assert.Null(new AgentListenerSettings(true, "127.0.0.1", 7443).Validate());
        Assert.NotNull(new AgentListenerSettings(true, "0.0.0.0", 7443).Validate());
        Assert.NotNull(new AgentListenerSettings(true, "8.8.8.8", 7443).Validate());
        Assert.NotNull(new AgentListenerSettings(true, "192.168.0.10", 80).Validate());
        Assert.NotNull(new AgentListenerSettings(true, "nas.local", 7443).Validate());
    }

    /// <summary>
    /// The whole path on this computer: the agent endpoint over real HTTPS (self-signed certificate, pinned), enrollment,
    /// the agent service picking up a job, scanning a local test server with the shared scanner and uploading the result.
    /// </summary>
    [Fact]
    public async Task An_enrolled_agent_scans_over_https_and_its_results_reach_weles()
    {
        var options = new ScanOptions { UseIcmp = false, UseMdns = false, ConnectTimeoutMs = 800, BannerTimeoutMs = 600, ProbeTimeoutMs = 1500, LivenessPorts = [1] };
        await using var env = await SetupAsync(options);
        await using var ssh = FakeServer.Banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n");
        var scope = await env.ScopeAsync("Pętla zwrotna", "127.0.0.1");

        var root = TempDirectory.Create();
        try
        {
            var paths = WelesPaths.Resolve(root);
            paths.EnsureCreated();
            var port = FreePort();
            var settings = new AgentListenerSettings(true, "127.0.0.1", port);
            using var certificate = AgentCertificate.LoadOrCreate(paths, settings.Address);
            var pin = AgentProtocol.Pin(certificate.RawData);

            var builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, port, l => l.UseHttps(certificate)));
            builder.Services.AddSingleton(new AgentListenerState(settings, pin, null));
            builder.Services.AddSingleton(env.Agents);
            await using var app = builder.Build();
            app.UseMiddleware<AgentApiMiddleware>();
            app.Run(c => { c.Response.StatusCode = 418; return Task.CompletedTask; }); // "the panel" – must never be reached on the agent port
            await app.StartAsync();

            var server = $"https://127.0.0.1:{port}";
            using (var raw = new HttpClient(new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true }))
            {
                Assert.Equal(HttpStatusCode.NotFound, (await raw.GetAsync(server + "/")).StatusCode);
                Assert.Equal(HttpStatusCode.NotFound, (await raw.GetAsync(server + "/settings")).StatusCode);
                Assert.Equal(HttpStatusCode.Unauthorized, (await raw.PostAsync(server + AgentProtocol.HeartbeatPath, new StringContent("{}", null, "application/json"))).StatusCode);
            }

            var (enrollment, _) = await env.Agents.CreateAsync("Lokalny", [scope]);
            // A wrong pin: the TLS connection itself is refused, nothing is sent.
            using (var wrong = new CentralClient(server, new string('a', 64)))
            {
                await Assert.ThrowsAsync<HttpRequestException>(() => wrong.EnrollAsync(new EnrollRequest(enrollment!.Code, System()), CancellationToken.None));
            }

            using (var client = new CentralClient(server, pin.ToUpperInvariant()))
            {
                var enrolled = await client.EnrollAsync(new EnrollRequest(enrollment!.Code, System()), CancellationToken.None);
                AgentConfigStore.Save(Path.Combine(root, "agent", "agent.json"), new AgentConfig(server, pin, enrolled.AgentId, enrolled.Name, enrolled.Token));
            }

            var configFile = Path.Combine(root, "agent", "agent.json");
            if (!OperatingSystem.IsWindows()) Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(configFile));
            var config = AgentConfigStore.Load(configFile)!;
            var agentId = config.AgentId;
            var start = await env.Agents.StartScanAsync(agentId, scope, ssh.Port.ToString());
            Assert.True(start.Success, string.Join(" ", start.Errors));

            var oui = new OuiDatabase();
            var worker = new AgentWorker(new AgentPaths(configFile), oui, new LocalNetworkDiscovery(oui), Options.Create(options), NullLogger<AgentWorker>.Instance);
            await worker.StartAsync(CancellationToken.None);
            try
            {
                Scan? scan = null;
                for (var i = 0; i < 120 && scan?.Status is not (ScanStatus.Completed or ScanStatus.Failed); i++)
                {
                    await Task.Delay(500);
                    await using var db = env.Db.CreateDbContext();
                    scan = await db.Scans.AsNoTracking().SingleAsync(s => s.Id == start.Id);
                }

                Assert.Equal(ScanStatus.Completed, scan!.Status);
                await using var check = env.Db.CreateDbContext();
                var host = await check.DiscoveredHosts.Include(h => h.Ports).ThenInclude(p => p.Service).SingleAsync(h => h.ScanId == start.Id);
                Assert.Equal("127.0.0.1", host.IpAddress);
                var service = host.Ports.Single(p => p.Port == ssh.Port).Service!;
                Assert.Equal("OpenSSH", service.Product);
                Assert.Contains(await check.ScanEvents.Where(e => e.ScanId == start.Id).Select(e => e.Message).ToListAsync(), m => m.Contains("przez agenta „Lokalny”"));
                var stored = await check.Agents.SingleAsync(a => a.Id == agentId);
                Assert.Equal("127.0.0.1", stored.LastAddress);
                Assert.NotNull(JsonSerializer.Deserialize<AgentSystemInfo>(stored.SystemInfoJson!, AgentProtocol.Json));
            }
            finally
            {
                await worker.StopAsync(CancellationToken.None);
                await app.StopAsync();
            }
        }
        finally
        {
            TempDirectory.Delete(root);
        }
    }

    private static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }
}
