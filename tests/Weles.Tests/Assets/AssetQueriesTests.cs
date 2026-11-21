using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Rules;
using Weles.Infrastructure.Assets;
using Weles.Infrastructure.Queries;
using Weles.Infrastructure.Scanning;
using Weles.Tests.Support;

namespace Weles.Tests.Assets;

/// <summary>Inventory read model on a real SQLite database, data written by the production ScanResultWriter.</summary>
public class AssetQueriesTests
{
    private static HostScanResult Host(string ip, string? mac, params int[] ports) => new(
        System.Net.IPAddress.Parse(ip), DiscoveryMethod.TcpConnect, null, null, null, mac, null, false,
        new HostClassification(AssetType.LinuxHost, "Linux", 60, ["test"]),
        ports.Select(p => new PortScanResult(p, "syn-ack", new ServiceProbeResult(
            new Weles.Core.Models.ServiceIdentification { ServiceName = "ssh", Product = "OpenSSH", Version = p == 22 ? "8.9p1" : null, Method = "banner", Confidence = 90 }, null))).ToList());

    private static async Task<int> CompletedScanAsync(TestDatabase testDb, ScanTarget target, string cidr, DateTime started, ScanStatus status = ScanStatus.Completed)
    {
        await using var db = testDb.CreateDbContext();
        db.Attach(target);
        var scan = new Scan
        {
            ScanTarget = target, Status = status, PortSpecification = "quick", CreatedAt = started, StartedAt = started, CompletedAt = started.AddMinutes(1),
            ScopeSnapshot = JsonSerializer.Serialize(new[] { new { Value = cidr, IsExclusion = false } })
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
    public async Task Statuses_and_history_across_scans()
    {
        var (testDb, writer, target) = await SetupAsync();
        await using var _ = testDb;

        var s1 = await CompletedScanAsync(testDb, target, "10.0.0.0/24", TestData.Now.AddDays(-2));
        await writer.SaveHostAsync(s1, Host("10.0.0.5", "aa:aa:aa:00:00:05", 22));
        await writer.SaveHostAsync(s1, Host("10.0.0.6", "aa:aa:aa:00:00:06", 80));

        var s2 = await CompletedScanAsync(testDb, target, "10.0.0.0/24", TestData.Now.AddDays(-1));
        await writer.SaveHostAsync(s2, Host("10.0.0.5", "aa:aa:aa:00:00:05", 22, 3389));
        await writer.SaveHostAsync(s2, Host("10.0.0.7", "aa:aa:aa:00:00:07"));

        var s3 = await CompletedScanAsync(testDb, target, "10.0.9.0/24", TestData.Now); // another network
        var cancelled = await CompletedScanAsync(testDb, target, "10.0.8.0/24", TestData.Now, ScanStatus.Cancelled);
        await writer.SaveHostAsync(cancelled, Host("10.0.8.8", null));

        var queries = new AssetQueries(testDb);
        var all = (await queries.LoadAllAsync()).ToDictionary(a => a.IpAddress!);

        Assert.Equal(AssetStatus.Active, all["10.0.0.5"].Status);
        Assert.Equal(AssetStatus.Intermittent, all["10.0.0.6"].Status); // one silent covering scan – below the inactivity threshold
        Assert.Equal((1, 2, 1), (all["10.0.0.6"].Presence!.ConsecutiveMisses, all["10.0.0.6"].Presence!.Covered, all["10.0.0.6"].Presence!.Seen));
        Assert.Equal(AssetStatus.New, all["10.0.0.7"].Status);
        Assert.Equal(AssetStatus.NotCovered, all["10.0.8.8"].Status); // only seen in a cancelled scan
        Assert.Equal([22, 3389], all["10.0.0.5"].OpenPorts);
        Assert.Contains("OpenSSH 8.9p1", all["10.0.0.5"].Products);
        Assert.Equal(2, all["10.0.0.5"].ObservationCount);

        var detail = (await queries.GetAsync(all["10.0.0.5"].Id))!;
        Assert.Equal(2, detail.Observations.Count);
        Assert.Contains(detail.Observations[0].ChangesSincePrevious, c => c.Kind == AssetChangeKind.PortOpened && c.Port == 3389);
        Assert.Empty(detail.Observations[1].ChangesSincePrevious);

        var missing = (await queries.GetAsync(all["10.0.0.6"].Id))!;
        Assert.Equal([s2], missing.Absences.Select(a => a.ScanId));
        Assert.DoesNotContain(missing.Absences, a => a.ScanId == s3);
    }

    [Fact]
    public async Task User_fields_survive_the_next_scan_and_clearing_name_restores_auto_name()
    {
        var (testDb, writer, target) = await SetupAsync();
        await using var _ = testDb;
        var service = new AssetService(testDb, NullLogger<AssetService>.Instance);

        var s1 = await CompletedScanAsync(testDb, target, "10.0.0.0/24", TestData.Now.AddDays(-1));
        await writer.SaveHostAsync(s1, Host("10.0.0.170", "aa:97:2c:1a:b1:5a"));
        int id;
        await using (var db = testDb.CreateDbContext()) id = (await db.Assets.SingleAsync()).Id;

        var update = await service.UpdateAsync(id, new AssetEditInput("Telefon Xiaomi", AssetType.MobileDevice, AssetCriticality.High, "Telefon właściciela"));
        Assert.True(update.Success);

        var s2 = await CompletedScanAsync(testDb, target, "10.0.0.0/24", TestData.Now);
        await writer.SaveHostAsync(s2, Host("10.0.0.170", "aa:97:2c:1a:b1:5a", 5555));

        await using (var db = testDb.CreateDbContext())
        {
            var asset = await db.Assets.SingleAsync();
            Assert.Equal("Telefon Xiaomi", asset.DisplayName);
            Assert.Equal(AssetType.MobileDevice, asset.EffectiveType);
            Assert.Equal(AssetType.LinuxHost, asset.AssetType); // detection keeps updating underneath
            Assert.Equal(AssetCriticality.High, asset.Criticality);
            Assert.Equal("Telefon właściciela", asset.Notes);
        }

        await service.UpdateAsync(id, new AssetEditInput("  ", null, AssetCriticality.Medium, null));
        await using (var db = testDb.CreateDbContext())
        {
            var asset = await db.Assets.SingleAsync();
            Assert.Equal("10.0.0.170", asset.DisplayName);
            Assert.Null(asset.CustomName);
            Assert.Equal(AssetType.LinuxHost, asset.EffectiveType);
        }
    }

    [Fact]
    public async Task Invalid_edits_are_rejected()
    {
        var (testDb, _, _) = await SetupAsync();
        await using var __ = testDb;
        var service = new AssetService(testDb, NullLogger<AssetService>.Instance);

        Assert.False((await service.UpdateAsync(999, new AssetEditInput("x", null, AssetCriticality.Low, null))).Success);
        var tooLong = await service.UpdateAsync(1, new AssetEditInput(new string('x', 300), (AssetType)99, (AssetCriticality)42, new string('n', 5000)));
        Assert.False(tooLong.Success);
        Assert.Equal(4, tooLong.Errors.Count);
    }
}
