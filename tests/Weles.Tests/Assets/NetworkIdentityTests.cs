using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Queries;
using Weles.Infrastructure.Scanning;
using Weles.Tests.Support;

namespace Weles.Tests.Assets;

/// <summary>
/// Two networks with the same private range (home Wi‑Fi and an office cable, both 192.168.0.0/24) and one laptop
/// moving between them – the situation found on the user's real networks on 2026‑11‑19.
/// </summary>
public class NetworkIdentityTests
{
    private const string HomeGateway = "68:7f:f0:72:00:14";
    private const string OfficeGateway = "c0:4a:00:ee:19:4a";
    private const string LaptopWifi = "aa:bb:cc:00:00:01";
    private const string LaptopCable = "aa:bb:cc:00:00:02";

    [Fact]
    public void Fingerprints_are_normalised_and_unknown_networks_are_not_told_apart()
    {
        Assert.Equal("aa:00:00:00:00:01,bb:00:00:00:00:02", NetworkIdentity.Fingerprint(["BB:00:00:00:00:02", null, "aa:00:00:00:00:01", "aa:00:00:00:00:01"]));
        Assert.Null(NetworkIdentity.Fingerprint([null, " "]));
        Assert.True(NetworkIdentity.SameNetwork(HomeGateway, HomeGateway));
        Assert.True(NetworkIdentity.SameNetwork($"{HomeGateway},{OfficeGateway}", OfficeGateway));
        Assert.False(NetworkIdentity.SameNetwork(HomeGateway, OfficeGateway));
        Assert.True(NetworkIdentity.SameNetwork(null, OfficeGateway));
    }

    [Fact]
    public void A_scan_of_another_network_with_the_same_range_does_not_make_a_device_missing()
    {
        var coverage = ScopeCoverage.FromSnapshot(JsonSerializer.Serialize(new[] { new { Value = "192.168.0.0/24", IsExclusion = false } }));
        var scans = new List<CompletedScanCoverage>
        {
            new(2, TestData.Now, coverage, OfficeGateway),
            new(1, TestData.Now.AddDays(-1), coverage, HomeGateway),
        };

        var tv = AssetStatusRules.Evaluate("192.168.0.226", scans, new HashSet<int> { 1 }, 1, HomeGateway);
        Assert.Equal(1, tv.ReferenceScanId);
        Assert.Equal(AssetStatus.Unknown, tv.Status); // last confirmed at home, the office has been scanned since
        Assert.Empty(AssetStatusRules.Absences("192.168.0.226", scans, new HashSet<int> { 1 }, TestData.Now.AddDays(-1), HomeGateway));

        // On the same network it is missing.
        Assert.Equal(AssetStatus.Missing, AssetStatusRules.Evaluate("192.168.0.226", scans, new HashSet<int> { 1 }, 1, OfficeGateway).Status);
    }

    [Fact]
    public void Devices_of_a_network_left_behind_are_unknown_until_it_is_scanned_again()
    {
        var coverage = ScopeCoverage.FromSnapshot(JsonSerializer.Serialize(new[] { new { Value = "192.168.0.0/24", IsExclusion = false } }));
        var loopback = ScopeCoverage.FromSnapshot(JsonSerializer.Serialize(new[] { new { Value = "127.0.0.1", IsExclusion = false } }));
        CompletedScanCoverage Home(int id, int day) => new(id, TestData.Now.AddDays(day), coverage, HomeGateway);
        CompletedScanCoverage Office(int id, int day) => new(id, TestData.Now.AddDays(day), coverage, OfficeGateway);

        // Seen at home, then the laptop moved to the office and scanned there.
        List<CompletedScanCoverage> scans = [Office(2, 0), Home(1, -1)];
        Assert.Equal(AssetStatus.Unknown, AssetStatusRules.Evaluate("192.168.0.50", scans, new HashSet<int> { 1 }, 1, HomeGateway).Status);
        Assert.Equal(AssetStatus.Unknown, AssetStatusRules.Evaluate("192.168.0.51", [Office(3, 0), Home(2, -1), Home(1, -2)], new HashSet<int> { 1 }, 1, HomeGateway).Status);

        // Back home and scanned again: judged normally.
        scans = [Home(3, 1), Office(2, 0), Home(1, -1)];
        Assert.Equal(AssetStatus.Active, AssetStatusRules.Evaluate("192.168.0.50", scans, new HashSet<int> { 1, 3 }, 1, HomeGateway).Status);
        Assert.Equal(AssetStatus.Missing, AssetStatusRules.Evaluate("192.168.0.51", scans, new HashSet<int> { 1 }, 1, HomeGateway).Status);

        // Office devices stay active; a later scan without network identity (loopback) changes nothing.
        scans = [new(4, TestData.Now.AddDays(2), loopback), Office(2, 0)];
        Assert.Equal(AssetStatus.New, AssetStatusRules.Evaluate("192.168.0.60", scans, new HashSet<int> { 2 }, 2, OfficeGateway).Status);

        // A device whose network is not identified (routed subnet, VPN) is never "left behind".
        Assert.Equal(AssetStatus.New, AssetStatusRules.Evaluate("10.8.0.5", [Office(2, 0), Home(1, -1)], new HashSet<int> { 1 }, 1, null).Status);
    }

    private static HostScanResult Host(string ip, string? mac, string? hostname = null, bool gateway = false, IReadOnlySet<string>? localMacs = null) => new(
        System.Net.IPAddress.Parse(ip), DiscoveryMethod.TcpConnect, null, null, hostname, mac, null, gateway,
        new HostClassification(AssetType.LinuxHost, "Linux", 60, ["test"]), [], null, localMacs);

    private static async Task<int> ScanAsync(TestDatabase testDb, ScanTarget target, string? network, DateTime started)
    {
        await using var db = testDb.CreateDbContext();
        db.Attach(target);
        var scan = new Scan
        {
            ScanTarget = target, Status = ScanStatus.Completed, PortSpecification = "quick", CreatedAt = started, StartedAt = started, CompletedAt = started.AddMinutes(1),
            ScopeSnapshot = JsonSerializer.Serialize(new[] { new { Value = "192.168.0.0/24", IsExclusion = false } }), NetworkFingerprint = network
        };
        db.Scans.Add(scan);
        await db.SaveChangesAsync();
        return scan.Id;
    }

    private static async Task<(TestDatabase Db, ScanResultWriter Writer, ScanTarget Target)> SetupAsync()
    {
        var testDb = await TestDatabase.CreateAsync();
        await using var db = testDb.CreateDbContext();
        var target = TestData.ApprovedTarget();
        db.ScanTargets.Add(target);
        await db.SaveChangesAsync();
        return (testDb, new ScanResultWriter(testDb, TimeProvider.System), target);
    }

    [Fact]
    public async Task Devices_without_mac_are_not_merged_across_networks()
    {
        var (testDb, writer, target) = await SetupAsync();
        await using var _ = testDb;

        // A device behind a router (no MAC) at the same IP with the same name on two different networks.
        var home = await ScanAsync(testDb, target, HomeGateway, TestData.Now.AddDays(-1));
        await writer.SaveHostAsync(home, Host("192.168.0.50", null, "printer.local"));
        var office = await ScanAsync(testDb, target, OfficeGateway, TestData.Now);
        await writer.SaveHostAsync(office, Host("192.168.0.50", null, "printer.local"));
        var homeAgain = await ScanAsync(testDb, target, HomeGateway, TestData.Now.AddHours(1));
        await writer.SaveHostAsync(homeAgain, Host("192.168.0.50", null, "printer.local"));

        await using var db = testDb.CreateDbContext();
        Assert.Equal(2, await db.Assets.CountAsync());
        var observations = await db.DiscoveredHosts.OrderBy(h => h.ScanId).Select(h => h.AssetId).ToListAsync();
        Assert.Equal(observations[0], observations[2]);
        Assert.NotEqual(observations[0], observations[1]);
    }

    [Fact]
    public async Task This_machine_found_over_wifi_and_cable_is_one_asset_with_user_fields_kept()
    {
        var (testDb, writer, target) = await SetupAsync();
        await using var _ = testDb;
        IReadOnlySet<string> laptop = new HashSet<string> { LaptopWifi, LaptopCable };

        var home = await ScanAsync(testDb, target, HomeGateway, TestData.Now.AddDays(-1));
        await writer.SaveHostAsync(home, Host("192.168.0.109", LaptopWifi, "laptop", localMacs: laptop));
        int wifiAsset;
        await using (var db = testDb.CreateDbContext())
        {
            var a = await db.Assets.SingleAsync();
            a.CustomName = "Mój laptop";
            await db.SaveChangesAsync();
            wifiAsset = a.Id;
        }

        // Duplicate created by an older version: the cable interface recorded as a separate asset.
        var office = await ScanAsync(testDb, target, OfficeGateway, TestData.Now);
        await using (var db = testDb.CreateDbContext())
        {
            db.Assets.Add(new Asset { DisplayName = "laptop", MacAddress = LaptopCable, PrimaryIpAddress = "192.168.0.102", FirstSeenAt = DateTime.UtcNow.AddMinutes(1), LastSeenAt = DateTime.UtcNow.AddMinutes(1), Notes = "biurko" });
            await db.SaveChangesAsync();
        }

        await writer.SaveHostAsync(office, Host("192.168.0.102", LaptopCable, "laptop", localMacs: laptop));

        await using (var db = testDb.CreateDbContext())
        {
            var asset = await db.Assets.SingleAsync();
            Assert.Equal(wifiAsset, asset.Id);
            Assert.Equal("Mój laptop", asset.DisplayName);
            Assert.Equal("biurko", asset.Notes);
            Assert.Equal(LaptopCable, asset.MacAddress);
            Assert.Equal("192.168.0.102", asset.PrimaryIpAddress);
            Assert.Equal(2, await db.DiscoveredHosts.CountAsync(h => h.AssetId == asset.Id));
        }

        var detail = await new AssetQueries(testDb).GetAsync(wifiAsset);
        Assert.Equal(AssetStatus.Active, detail!.Presence.Status);
    }

    [Fact]
    public async Task Migration_fills_the_network_of_existing_scans_from_their_observed_gateway()
    {
        var testDb = await TestDatabase.CreateAsync();
        await using var _ = testDb;
        await using (var db = testDb.CreateDbContext())
        {
            await db.GetService<IMigrator>().MigrateAsync("20261119092917_Stage3DeviceModel");
            await db.Database.ExecuteSqlRawAsync("""
                INSERT INTO ScanTargets (Id, Name, IsApproved, AllowPublicAddresses, IsDemo, CreatedAt) VALUES (1, 't', 1, 0, 0, '2026-11-18');
                INSERT INTO Scans (Id, ScanTargetId, Status, "Trigger", PortSpecification, CreatedAt, HostsTargeted, HostsProbed, PortCount, HostsAlive, OpenPorts, IsDemo) VALUES (1, 1, 2, 0, 'quick', '2026-11-18', 0, 0, 0, 0, 0, 0);
                INSERT INTO Scans (Id, ScanTargetId, Status, "Trigger", PortSpecification, CreatedAt, HostsTargeted, HostsProbed, PortCount, HostsAlive, OpenPorts, IsDemo) VALUES (2, 1, 2, 0, 'quick', '2026-11-19', 0, 0, 0, 0, 0, 0);
                INSERT INTO DiscoveredHosts (ScanId, IpAddress, MacAddress, DiscoveryMethods, IsGateway, AssetTypeGuess, ClassificationConfidence, DiscoveredAt) VALUES (1, '192.168.0.1', '68:7F:F0:72:00:14', 1, 1, 4, 85, '2026-11-18');
                INSERT INTO DiscoveredHosts (ScanId, IpAddress, MacAddress, DiscoveryMethods, IsGateway, AssetTypeGuess, ClassificationConfidence, DiscoveredAt) VALUES (1, '192.168.0.5', 'aa:aa:aa:aa:aa:aa', 1, 0, 0, 0, '2026-11-18');
                """);
            await db.Database.MigrateAsync();
        }

        await using (var db = testDb.CreateDbContext())
        {
            var networks = await db.Scans.OrderBy(s => s.Id).Select(s => s.NetworkFingerprint).ToListAsync();
            Assert.Equal([HomeGateway, null], networks);
        }

        SqliteConnection.ClearAllPools();
    }

    private sealed class FakeCurrentNetwork(params AttachedNetwork[] networks) : ICurrentNetworkProvider
    {
        public IReadOnlyList<AttachedNetwork> GetAttachedNetworks() => networks;
    }

    [Fact]
    public async Task Current_network_view_hides_only_other_identified_networks()
    {
        var testDb = await TestDatabase.CreateAsync();
        await using var _ = testDb;
        var writer = new ScanResultWriter(testDb, TimeProvider.System);
        await writer.EnsureSegmentsAsync([
            new("192.168.0.0/24", "192.168.0.1", HomeGateway, "TP-LINK TECHNOLOGIES CO.,LTD."),
            new("192.168.0.0/24", "192.168.0.1", OfficeGateway, "TP-LINK TECHNOLOGIES CO.,LTD."),
            new("10.8.0.0/24", null, null, null)]);
        int home, office, vpn;
        await using (var db = testDb.CreateDbContext())
        {
            home = (await db.NetworkSegments.SingleAsync(s => s.GatewayMac == HomeGateway)).Id;
            office = (await db.NetworkSegments.SingleAsync(s => s.GatewayMac == OfficeGateway)).Id;
            vpn = (await db.NetworkSegments.SingleAsync(s => s.Cidr == "10.8.0.0/24")).Id;
        }

        var atOffice = await new AssetQueries(testDb, new FakeCurrentNetwork(new AttachedNetwork("192.168.0.0/24", OfficeGateway))).CurrentNetworkAsync();
        Assert.Equal([home], atOffice.OtherNetworkSegmentIds);
        Assert.Equal($"192.168.0.0/24 · TP-LINK {OfficeGateway}", atOffice.Description);

        var atHome = await new AssetQueries(testDb, new FakeCurrentNetwork(new AttachedNetwork("192.168.0.0/24", HomeGateway))).CurrentNetworkAsync();
        Assert.Equal([office], atHome.OtherNetworkSegmentIds);
        Assert.DoesNotContain(vpn, atHome.OtherNetworkSegmentIds);

        // Elsewhere (a café): both identified networks are "other"; without any interface nothing is hidden.
        var cafe = await new AssetQueries(testDb, new FakeCurrentNetwork(new AttachedNetwork("172.20.10.0/28", "11:22:33:44:55:66"))).CurrentNetworkAsync();
        Assert.Equal(new HashSet<int> { home, office }, cafe.OtherNetworkSegmentIds);
        Assert.Empty((await new AssetQueries(testDb, new FakeCurrentNetwork()).CurrentNetworkAsync()).OtherNetworkSegmentIds);
    }

    [Fact]
    public async Task Migration_splits_a_segment_shared_by_two_networks()
    {
        var testDb = await TestDatabase.CreateAsync();
        await using var _ = testDb;
        await using (var db = testDb.CreateDbContext())
        {
            await db.GetService<IMigrator>().MigrateAsync("20261119101255_Stage3NetworkIdentity");
            await db.Database.ExecuteSqlRawAsync("""
                INSERT INTO ScanTargets (Id, Name, IsApproved, AllowPublicAddresses, IsDemo, CreatedAt) VALUES (1, 't', 1, 0, 0, '2026-11-18');
                INSERT INTO Scans (Id, ScanTargetId, Status, "Trigger", PortSpecification, CreatedAt, HostsTargeted, HostsProbed, PortCount, HostsAlive, OpenPorts, IsDemo, NetworkFingerprint) VALUES (1, 1, 2, 0, 'quick', '2026-11-18', 0, 0, 0, 0, 0, 0, '68:7f:f0:72:00:14');
                INSERT INTO Scans (Id, ScanTargetId, Status, "Trigger", PortSpecification, CreatedAt, HostsTargeted, HostsProbed, PortCount, HostsAlive, OpenPorts, IsDemo, NetworkFingerprint) VALUES (2, 1, 2, 0, 'quick', '2026-11-19', 0, 0, 0, 0, 0, 0, 'c0:4a:00:ee:19:4a');
                INSERT INTO NetworkSegments (Id, Cidr, Gateway, FirstSeenAt, LastSeenAt) VALUES (1, '192.168.0.0/24', '192.168.0.1', '2026-11-18', '2026-11-19');
                INSERT INTO Assets (Id, DisplayName, PrimaryIpAddress, AssetType, Criticality, NetworkSegmentId, FirstSeenAt, LastSeenAt, IsDemo) VALUES (1, 'tv', '192.168.0.226', 0, 2, 1, '2026-11-18', '2026-11-18', 0);
                INSERT INTO Assets (Id, DisplayName, PrimaryIpAddress, AssetType, Criticality, NetworkSegmentId, FirstSeenAt, LastSeenAt, IsDemo) VALUES (2, 'router', '192.168.0.1', 4, 2, 1, '2026-11-19', '2026-11-19', 0);
                INSERT INTO DiscoveredHosts (ScanId, AssetId, IpAddress, MacAddress, Vendor, DiscoveryMethods, IsGateway, AssetTypeGuess, ClassificationConfidence, DiscoveredAt) VALUES (1, 1, '192.168.0.226', NULL, NULL, 1, 0, 0, 0, '2026-11-18');
                INSERT INTO DiscoveredHosts (ScanId, AssetId, IpAddress, MacAddress, Vendor, DiscoveryMethods, IsGateway, AssetTypeGuess, ClassificationConfidence, DiscoveredAt) VALUES (2, 2, '192.168.0.1', 'c0:4a:00:ee:19:4a', 'TP-LINK TECHNOLOGIES CO.,LTD.', 1, 1, 4, 85, '2026-11-19');
                """);
            await db.Database.MigrateAsync();
        }

        await using (var db = testDb.CreateDbContext())
        {
            var segments = await db.NetworkSegments.OrderBy(s => s.GatewayMac).ToListAsync();
            Assert.Equal([HomeGateway, OfficeGateway], segments.Select(s => s.GatewayMac));
            Assert.Equal("TP-LINK TECHNOLOGIES CO.,LTD.", segments[1].GatewayVendor);
            Assert.Equal(segments[0].Id, (await db.Assets.SingleAsync(a => a.Id == 1)).NetworkSegmentId);
            Assert.Equal(segments[1].Id, (await db.Assets.SingleAsync(a => a.Id == 2)).NetworkSegmentId);
        }

        SqliteConnection.ClearAllPools();
    }
}
