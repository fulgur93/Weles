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
        Assert.Equal("Linux", asset.OsFamily);
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
