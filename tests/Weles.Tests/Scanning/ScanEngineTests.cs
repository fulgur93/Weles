using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Scanning;
using Weles.Tests.Support;

namespace Weles.Tests.Scanning;

/// <summary>End-to-end scans of 127.0.0.1 against local fake services, persisted to a real SQLite database.</summary>
public class ScanEngineTests
{
    private sealed class Harness : IAsyncDisposable
    {
        public required TestDatabase Db { get; init; }
        public required ScanEngine Engine { get; init; }
        public required ScanTargetService Targets { get; init; }
        public required ScanCoordinator Coordinator { get; init; }

        public static async Task<Harness> CreateAsync(ScanOptions? options = null)
        {
            var db = await TestDatabase.CreateAsync();
            var opts = Options.Create(options ?? new ScanOptions { UseIcmp = false, ConnectTimeoutMs = 800, BannerTimeoutMs = 600, ProbeTimeoutMs = 1500, LivenessPorts = [1] });
            var oui = new OuiDatabase();
            var coordinator = new ScanCoordinator(TimeProvider.System);
            var writer = new ScanResultWriter(db, TimeProvider.System);
            return new Harness
            {
                Db = db,
                Coordinator = coordinator,
                Engine = new ScanEngine(db, writer, oui, new LocalNetworkDiscovery(oui), opts, TimeProvider.System, NullLogger<ScanEngine>.Instance),
                Targets = new ScanTargetService(db, coordinator, opts, TimeProvider.System, NullLogger<ScanTargetService>.Instance)
            };
        }

        public async Task<int> ApprovedTargetAsync(string include = "127.0.0.1")
        {
            var created = await Targets.CreateAsync(new ScanTargetInput("Loopback", null, include, null, false));
            Assert.True(created.Success, string.Join(" ", created.Errors));
            Assert.True((await Targets.ApproveAsync(created.Id!.Value, confirmedAuthorization: true)).Success);
            return created.Id!.Value;
        }

        public async Task<int> RunAsync(int targetId, string ports, CancellationToken ct = default)
        {
            var started = await Targets.StartScanAsync(targetId, ports, ct: ct);
            Assert.True(started.Success, string.Join(" ", started.Errors));
            var progress = Coordinator.GetProgress(started.Id!.Value)!;
            await Engine.RunAsync(started.Id!.Value, progress, ct);
            return started.Id!.Value;
        }

        public ValueTask DisposeAsync() => Db.DisposeAsync();
    }

    [Fact]
    public async Task Scan_of_loopback_discovers_ports_services_and_creates_an_asset()
    {
        await using var h = await Harness.CreateAsync();
        await using var ssh = FakeServer.Banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n");
        await using var web = FakeServer.Http("HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n<title>Intranet</title>");
        var target = await h.ApprovedTargetAsync();

        var scanId = await h.RunAsync(target, $"{ssh.Port},{web.Port}");

        await using var db = h.Db.CreateDbContext();
        var scan = await db.Scans.Include(s => s.Events).SingleAsync(s => s.Id == scanId);
        Assert.Equal(ScanStatus.Completed, scan.Status);
        Assert.Equal(1, scan.HostsTargeted);
        Assert.Equal(1, scan.HostsAlive);
        Assert.Equal(2, scan.OpenPorts);
        Assert.NotNull(scan.ScopeSnapshot);
        Assert.Contains(scan.Events, e => e.Message.Contains("Rozpoczęto"));
        Assert.Contains(scan.Events, e => e.Message.Contains("zakończony"));

        var host = await db.DiscoveredHosts.Include(x => x.Ports).ThenInclude(p => p.Service).SingleAsync();
        Assert.Equal("127.0.0.1", host.IpAddress);
        Assert.True(host.DiscoveryMethods.HasFlag(DiscoveryMethod.TcpConnect));
        var services = host.Ports.ToDictionary(p => p.Port, p => p.Service!);
        Assert.Equal(("OpenSSH", "8.2p1"), (services[ssh.Port].Product, services[ssh.Port].Version));
        Assert.Equal("Apache httpd", services[web.Port].Product);
        Assert.Contains("Ubuntu", services[ssh.Port].ExtraInfoJson);

        var asset = await db.Assets.SingleAsync();
        Assert.Equal(host.AssetId, asset.Id);
        Assert.Contains("WELES", asset.ClassificationReasons); // loopback = the machine running WELES
    }

    [Fact]
    public async Task Scan_with_no_live_hosts_is_completed_and_explains_the_empty_result()
    {
        // No ICMP and no liveness ports: every probed address stays silent, so the port phase is skipped entirely.
        await using var h = await Harness.CreateAsync(new ScanOptions
        {
            UseIcmp = false, UseMdns = false, LivenessPorts = [], ConnectTimeoutMs = 200, BannerTimeoutMs = 200, ProbeTimeoutMs = 200
        });
        var target = await h.ApprovedTargetAsync();

        var scanId = await h.RunAsync(target, "22");

        await using var db = h.Db.CreateDbContext();
        var scan = await db.Scans.Include(s => s.Events).SingleAsync(s => s.Id == scanId);
        Assert.Equal(ScanStatus.Completed, scan.Status);
        Assert.Equal(1, scan.HostsProbed); // was silently reset to 0 by FinishAsync's reload
        Assert.Equal(0, scan.HostsAlive);
        Assert.Contains(scan.Events, e => e.Level == ScanEventLevel.Warning && e.Message.Contains("Nie wykryto żadnych aktywnych hostów"));
    }

    [Fact]
    public async Task Connections_to_a_single_host_are_rate_limited()
    {
        // 30 closed ports at 10 connections/s per host (burst 2) cannot finish in under ~2.8 s.
        await using var h = await Harness.CreateAsync(new ScanOptions
        {
            UseIcmp = false, UseMdns = false, ConnectTimeoutMs = 800, LivenessPorts = [1], ConnectionsPerSecondPerHost = 10
        });
        await using var alive = FakeServer.Banner("SSH-2.0-OpenSSH_9.6\r\n");
        var target = await h.ApprovedTargetAsync();
        var closed = Enumerable.Range(0, 29).Select(_ => FreePort()).Distinct().ToList();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await h.RunAsync(target, string.Join(",", closed.Append(alive.Port)));
        Assert.True(sw.Elapsed >= TimeSpan.FromSeconds(2.2), $"Scan took {sw.Elapsed.TotalSeconds:0.00}s");
    }

    private static int FreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    [Fact]
    public async Task Second_scan_keeps_history_and_reuses_the_same_asset()
    {
        await using var h = await Harness.CreateAsync();
        await using var ssh = FakeServer.Banner("SSH-2.0-OpenSSH_8.2p1\r\n");
        var target = await h.ApprovedTargetAsync();

        await h.RunAsync(target, ssh.Port.ToString());
        await h.RunAsync(target, ssh.Port.ToString());

        await using var db = h.Db.CreateDbContext();
        Assert.Equal(2, await db.Scans.CountAsync(s => s.Status == ScanStatus.Completed));
        Assert.Equal(2, await db.DiscoveredHosts.CountAsync());
        Assert.Equal(1, await db.Assets.CountAsync());
    }

    [Fact]
    public async Task Closed_ports_are_not_stored()
    {
        await using var h = await Harness.CreateAsync();
        var target = await h.ApprovedTargetAsync();
        int closedPort;
        using (var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0)) { l.Start(); closedPort = ((IPEndPoint)l.LocalEndpoint).Port; }

        await h.RunAsync(target, closedPort.ToString());

        await using var db = h.Db.CreateDbContext();
        Assert.Equal(0, await db.DiscoveredPorts.CountAsync());
        Assert.Equal(1, await db.DiscoveredHosts.CountAsync()); // RST still proves the host is alive
    }

    [Fact]
    public async Task Unapproved_scope_cannot_be_scanned()
    {
        await using var h = await Harness.CreateAsync();
        var created = await h.Targets.CreateAsync(new ScanTargetInput("x", null, "127.0.0.1", null, false));

        var start = await h.Targets.StartScanAsync(created.Id!.Value, "quick");

        Assert.False(start.Success);
        Assert.Contains("zatwierdzony", start.Errors.Single());
    }

    [Fact]
    public async Task Engine_refuses_a_scan_whose_scope_lost_approval()
    {
        await using var h = await Harness.CreateAsync();
        var target = await h.ApprovedTargetAsync();
        var start = await h.Targets.StartScanAsync(target, "22");
        await h.Targets.RevokeApprovalAsync(target);

        await h.Engine.RunAsync(start.Id!.Value, h.Coordinator.GetProgress(start.Id!.Value)!, CancellationToken.None);

        await using var db = h.Db.CreateDbContext();
        var scan = await db.Scans.SingleAsync();
        Assert.Equal(ScanStatus.Failed, scan.Status);
        Assert.Equal(0, await db.DiscoveredHosts.CountAsync());
    }

    [Fact]
    public async Task Cancelled_scan_is_marked_and_keeps_partial_results()
    {
        await using var h = await Harness.CreateAsync();
        var target = await h.ApprovedTargetAsync("127.0.0.1-127.0.0.40");
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));

        var start = await h.Targets.StartScanAsync(target, "1-2000");
        await h.Engine.RunAsync(start.Id!.Value, h.Coordinator.GetProgress(start.Id!.Value)!, cts.Token);

        await using var db = h.Db.CreateDbContext();
        var scan = await db.Scans.Include(s => s.Events).SingleAsync();
        Assert.Equal(ScanStatus.Cancelled, scan.Status);
        Assert.NotNull(scan.CompletedAt);
        Assert.Contains(scan.Events, e => e.Message.Contains("zatrzymany"));
    }
}

public class ScanResultWriterTests
{
    [Fact]
    public async Task Segment_keeps_gateway_when_the_same_cidr_comes_from_scope_and_interface()
    {
        // Regression from a real scan: the scope entry (no gateway) shadowed the interface (with gateway).
        await using var testDb = await TestDatabase.CreateAsync();
        var writer = new ScanResultWriter(testDb, TimeProvider.System);

        const string home = "68:7f:f0:72:00:14";
        await writer.EnsureSegmentsAsync([new("192.168.0.0/24", null, home, null), new("192.168.0.0/24", "192.168.0.1", home, "TP-LINK"), new("10.0.0.0/24", null, null, null)]);
        await writer.EnsureSegmentsAsync([new("192.168.0.0/24", null, home, null)]);

        await using var db = testDb.CreateDbContext();
        var segments = await db.NetworkSegments.OrderBy(s => s.Cidr).ToListAsync();
        Assert.Equal(2, segments.Count);
        Assert.Equal("192.168.0.1", segments.Single(s => s.Cidr == "192.168.0.0/24").Gateway);
    }

    [Fact]
    public async Task Same_cidr_on_two_networks_gives_two_segments_and_hosts_land_in_their_own()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        var writer = new ScanResultWriter(testDb, TimeProvider.System);
        const string home = "68:7f:f0:72:00:14", office = "c0:4a:00:ee:19:4a";

        // A segment created before the gateway was known is adopted by the first network.
        await writer.EnsureSegmentsAsync([new("192.168.0.0/24", null, null, null)]);
        await writer.EnsureSegmentsAsync([new("192.168.0.0/24", "192.168.0.1", home, "TP-LINK")]);
        await writer.EnsureSegmentsAsync([new("192.168.0.0/24", "192.168.0.1", office, "TP-LINK")]);

        await using var db = testDb.CreateDbContext();
        var segments = await db.NetworkSegments.OrderBy(s => s.Id).ToListAsync();
        Assert.Equal([home, office], segments.Select(s => s.GatewayMac));

        Assert.Equal(segments[0].Id, await ScanResultWriter.FindSegmentIdAsync(db, IPAddress.Parse("192.168.0.50"), home));
        Assert.Equal(segments[1].Id, await ScanResultWriter.FindSegmentIdAsync(db, IPAddress.Parse("192.168.0.50"), office));
        Assert.Null(await ScanResultWriter.FindSegmentIdAsync(db, IPAddress.Parse("192.168.0.50"), "11:22:33:44:55:66"));
    }
}

public class ScanTargetServiceTests
{
    private static async Task<(TestDatabase Db, ScanTargetService Service)> CreateAsync()
    {
        var db = await TestDatabase.CreateAsync();
        return (db, new ScanTargetService(db, new ScanCoordinator(TimeProvider.System), Options.Create(new ScanOptions()), TimeProvider.System, NullLogger<ScanTargetService>.Instance));
    }

    [Fact]
    public async Task Public_address_requires_explicit_permission()
    {
        var (db, svc) = await CreateAsync();
        await using var _ = db;

        var denied = await svc.CreateAsync(new ScanTargetInput("ext", null, "8.8.8.8", null, AllowPublicAddresses: false));
        var allowed = await svc.CreateAsync(new ScanTargetInput("ext", null, "8.8.8.8", null, AllowPublicAddresses: true));

        Assert.False(denied.Success);
        Assert.Contains("publiczne", denied.Errors.Single());
        Assert.True(allowed.Success);
    }

    [Fact]
    public async Task Invalid_entries_and_missing_name_are_reported_together()
    {
        var (db, svc) = await CreateAsync();
        await using var _ = db;

        var result = await svc.CreateAsync(new ScanTargetInput(" ", null, "10.0.0.0/8\nnot an ip!", null, false));

        Assert.False(result.Success);
        Assert.True(result.Errors.Count >= 3);
    }

    [Fact]
    public async Task Approval_requires_confirmation_and_editing_revokes_it()
    {
        var (db, svc) = await CreateAsync();
        await using var _ = db;
        var id = (await svc.CreateAsync(new ScanTargetInput("LAN", null, "192.168.10.0/24", "192.168.10.1", false))).Id!.Value;

        Assert.False((await svc.ApproveAsync(id, confirmedAuthorization: false)).Success);
        Assert.True((await svc.ApproveAsync(id, confirmedAuthorization: true)).Success);
        Assert.True((await svc.ListAsync()).Single().IsApproved);

        await svc.UpdateAsync(id, new ScanTargetInput("LAN", null, "192.168.10.0/24", null, false));

        var summary = (await svc.ListAsync()).Single();
        Assert.False(summary.IsApproved);
        Assert.Empty(summary.Excludes);
    }

    [Fact]
    public async Task Scope_with_history_cannot_be_deleted_but_empty_one_can()
    {
        var (db, svc) = await CreateAsync();
        await using var _ = db;
        var used = (await svc.CreateAsync(new ScanTargetInput("used", null, "10.0.0.1", null, false))).Id!.Value;
        var unused = (await svc.CreateAsync(new ScanTargetInput("unused", null, "10.0.0.2", null, false))).Id!.Value;
        await svc.ApproveAsync(used, true);
        await svc.StartScanAsync(used, "22");

        Assert.False((await svc.DeleteAsync(used)).Success);
        Assert.True((await svc.DeleteAsync(unused)).Success);
    }

    [Fact]
    public async Task Only_one_active_scan_per_scope()
    {
        var (db, svc) = await CreateAsync();
        await using var _ = db;
        var id = (await svc.CreateAsync(new ScanTargetInput("LAN", null, "10.0.0.1", null, false))).Id!.Value;
        await svc.ApproveAsync(id, true);

        Assert.True((await svc.StartScanAsync(id, "22")).Success);
        Assert.False((await svc.StartScanAsync(id, "22")).Success);
    }

    [Fact]
    public async Task Preview_reports_address_count_and_warnings()
    {
        var (db, svc) = await CreateAsync();
        await using var _ = db;

        var preview = await svc.PreviewAsync(new ScanTargetInput("LAN", null, "192.168.1.0/24", "192.168.1.0/25", false));

        Assert.Empty(preview.Errors);
        Assert.Equal(127, preview.AddressCount); // .128–.254: excluding a /25 removes the whole network
    }
}
