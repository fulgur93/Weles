using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Rules;
using Weles.Infrastructure.Scanning;
using Weles.Tests.Support;

namespace Weles.Tests.Assets;

/// <summary>
/// The user's Raspberry Pi 4 (2026-11-19) answered on cable (dc:a6:32:b7:7e:b8) and Wi‑Fi (dc:a6:32:b7:7e:b9) with the
/// same SSH host key – one device, two interfaces.
/// </summary>
public class SshHostKeyCorrelationTests
{
    private const string PiKey = "SHA256:N3EJXFRdmFZwk0MRbIR2CCRvpJGFUxOGJRrUy9iFoLQ";

    private static HostScanResult Host(string ip, string mac, string? hostKey) => new(
        System.Net.IPAddress.Parse(ip), DiscoveryMethod.TcpConnect, null, 64, null, mac, "Raspberry Pi Trading Ltd", false,
        new HostClassification(AssetType.LinuxHost, "Linux", 60, ["test"]),
        [new PortScanResult(22, "syn-ack", new ServiceProbeResult(new Weles.Core.Models.ServiceIdentification
        {
            ServiceName = "ssh", Product = "OpenSSH", Version = "8.4p1", Method = "banner", Confidence = 95,
            Extra = hostKey is null ? [] : new() { ["ssh.hostKey"] = hostKey, ["ssh.hostKeyType"] = "ssh-ed25519" }
        }, null))]);

    private static async Task<(TestDatabase Db, ScanResultWriter Writer, ScanTarget Target)> SetupAsync()
    {
        var testDb = await TestDatabase.CreateAsync();
        await using var db = testDb.CreateDbContext();
        var target = TestData.ApprovedTarget();
        db.ScanTargets.Add(target);
        await db.SaveChangesAsync();
        return (testDb, new ScanResultWriter(testDb, TimeProvider.System), target);
    }

    private static async Task<int> ScanAsync(TestDatabase testDb, ScanTarget target, DateTime started)
    {
        await using var db = testDb.CreateDbContext();
        db.Attach(target);
        var scan = new Scan
        {
            ScanTarget = target, Status = ScanStatus.Completed, PortSpecification = "quick", CreatedAt = started, StartedAt = started, CompletedAt = started.AddMinutes(1),
            ScopeSnapshot = JsonSerializer.Serialize(new[] { new { Value = "192.168.0.0/24", IsExclusion = false } })
        };
        db.Scans.Add(scan);
        await db.SaveChangesAsync();
        return scan.Id;
    }

    [Fact]
    public async Task Two_interfaces_with_the_same_host_key_are_one_device()
    {
        var (testDb, writer, target) = await SetupAsync();
        await using var _ = testDb;
        var scan = await ScanAsync(testDb, target, TestData.Now);
        await writer.SaveHostAsync(scan, Host("192.168.0.103", "dc:a6:32:b7:7e:b8", PiKey));
        await writer.SaveHostAsync(scan, Host("192.168.0.101", "dc:a6:32:b7:7e:b9", PiKey));

        await using var db = testDb.CreateDbContext();
        var asset = await db.Assets.SingleAsync();
        Assert.Equal("dc:a6:32:b7:7e:b8", asset.MacAddress);
        Assert.Equal(2, await db.DiscoveredHosts.CountAsync(h => h.AssetId == asset.Id));
    }

    [Fact]
    public async Task Existing_duplicates_are_merged_once_the_key_is_known_and_user_fields_survive()
    {
        var (testDb, writer, target) = await SetupAsync();
        await using var _ = testDb;

        // Older scans (before host keys were read): two separate assets.
        var old = await ScanAsync(testDb, target, TestData.Now.AddDays(-1));
        await writer.SaveHostAsync(old, Host("192.168.0.103", "dc:a6:32:b7:7e:b8", null));
        await writer.SaveHostAsync(old, Host("192.168.0.101", "dc:a6:32:b7:7e:b9", null));
        int wired, wifi;
        await using (var db = testDb.CreateDbContext())
        {
            Assert.Equal(2, await db.Assets.CountAsync());
            wired = (await db.Assets.SingleAsync(a => a.MacAddress == "dc:a6:32:b7:7e:b8")).Id;
            var w = await db.Assets.SingleAsync(a => a.MacAddress == "dc:a6:32:b7:7e:b9");
            w.CustomName = "Malinka";
            w.Criticality = AssetCriticality.High;
            wifi = w.Id;
            db.RiskFindings.Add(new RiskFinding { AssetId = wifi, ScanId = old, RuleId = "VERSION-DISCLOSURE", Title = "t", Category = "c", Port = 22, CreatedAt = TestData.Now, LastDetectedAt = TestData.Now });
            await db.SaveChangesAsync();
        }

        var current = await ScanAsync(testDb, target, TestData.Now);
        await writer.SaveHostAsync(current, Host("192.168.0.103", "dc:a6:32:b7:7e:b8", PiKey));
        await writer.SaveHostAsync(current, Host("192.168.0.101", "dc:a6:32:b7:7e:b9", PiKey));

        await using (var db = testDb.CreateDbContext())
        {
            var asset = await db.Assets.SingleAsync();
            Assert.Equal(wired, asset.Id);                   // the oldest record survives
            Assert.Equal("Malinka", asset.CustomName);       // the user's name from the other one is kept
            Assert.Equal(AssetCriticality.High, asset.Criticality);
            Assert.Equal(4, await db.DiscoveredHosts.CountAsync(h => h.AssetId == asset.Id));
            Assert.Equal(asset.Id, (await db.RiskFindings.SingleAsync()).AssetId);
        }
    }

    [Fact]
    public async Task Same_key_from_another_vendor_or_without_key_is_not_merged()
    {
        var (testDb, writer, target) = await SetupAsync();
        await using var _ = testDb;
        var scan = await ScanAsync(testDb, target, TestData.Now);
        // Some vendors ship one key on every unit: different OUI → kept apart.
        await writer.SaveHostAsync(scan, Host("192.168.0.20", "aa:bb:cc:00:00:01", PiKey));
        await writer.SaveHostAsync(scan, Host("192.168.0.21", "dc:a6:32:00:00:02", PiKey));
        await writer.SaveHostAsync(scan, Host("192.168.0.22", "dc:a6:32:00:00:03", null));
        await writer.SaveHostAsync(scan, Host("192.168.0.23", "dc:a6:32:00:00:04", "SHA256:other"));

        await using var db = testDb.CreateDbContext();
        Assert.Equal(4, await db.Assets.CountAsync());
    }
}

/// <summary>
/// End-to-end on a real, approved network and a copy of a real database:
/// WELES_LIVE_DB=/path/copy/weles.db WELES_LIVE_SCOPE="192.168.0.101\n192.168.0.103" WELES_LIVE_MAC_PREFIX=dc:a6:32.
/// Does nothing without the variables.
/// </summary>
public class SshHostKeyLiveTests
{
    private sealed class FileDb(string path) : IDbContextFactory<Weles.Infrastructure.Database.WelesDbContext>
    {
        public Weles.Infrastructure.Database.WelesDbContext CreateDbContext() =>
            new(new DbContextOptionsBuilder<Weles.Infrastructure.Database.WelesDbContext>().UseSqlite($"Data Source={path}").Options);
    }

    [Fact]
    public async Task Live_scan_merges_interfaces_of_one_device()
    {
        if (Environment.GetEnvironmentVariable("WELES_LIVE_DB") is not { Length: > 0 } path) return;
        var scope = Environment.GetEnvironmentVariable("WELES_LIVE_SCOPE")!.Replace("\\n", "\n");
        var prefix = Environment.GetEnvironmentVariable("WELES_LIVE_MAC_PREFIX")!;
        var db = new FileDb(path);
        await new Weles.Infrastructure.Database.DatabaseInitializer(db, Microsoft.Extensions.Logging.Abstractions.NullLogger<Weles.Infrastructure.Database.DatabaseInitializer>.Instance).InitializeAsync();

        await using (var ctx = db.CreateDbContext())
        {
            Console.WriteLine("LIVE before: " + string.Join(" | ", await ctx.Assets.Where(a => a.MacAddress!.StartsWith(prefix)).Select(a => $"#{a.Id} {a.DisplayName} {a.MacAddress}").ToListAsync()));
        }

        var opts = Microsoft.Extensions.Options.Options.Create(new ScanOptions());
        var oui = new Weles.Infrastructure.Discovery.OuiDatabase();
        var coordinator = new ScanCoordinator(TimeProvider.System);
        var writer = new ScanResultWriter(db, TimeProvider.System);
        var engine = new ScanEngine(db, writer, oui, new Weles.Infrastructure.Discovery.LocalNetworkDiscovery(oui), opts, TimeProvider.System, Microsoft.Extensions.Logging.Abstractions.NullLogger<ScanEngine>.Instance);
        var targets = new ScanTargetService(db, coordinator, opts, TimeProvider.System, Microsoft.Extensions.Logging.Abstractions.NullLogger<ScanTargetService>.Instance);
        var created = await targets.CreateAsync(new ScanTargetInput("Raspberry Pi – test kluczy SSH", null, scope, null, false));
        Assert.True(created.Success, string.Join(" ", created.Errors));
        Assert.True((await targets.ApproveAsync(created.Id!.Value, true)).Success);
        var started = await targets.StartScanAsync(created.Id!.Value, "22");
        await engine.RunAsync(started.Id!.Value, coordinator.GetProgress(started.Id!.Value)!, CancellationToken.None);

        await using (var ctx = db.CreateDbContext())
        {
            var assets = await ctx.Assets.Where(a => a.MacAddress!.StartsWith(prefix)).ToListAsync();
            var hosts = await ctx.DiscoveredHosts.Where(h => h.ScanId == started.Id).Include(h => h.Ports).ThenInclude(p => p.Service).ToListAsync();
            Console.WriteLine("LIVE scan: " + string.Join(" | ", hosts.Select(h => $"{h.IpAddress} {h.MacAddress} → #{h.AssetId} {h.Ports.FirstOrDefault()?.Service?.ExtraInfoJson}")));
            Console.WriteLine("LIVE after: " + string.Join(" | ", assets.Select(a => $"#{a.Id} {a.DisplayName} {a.MacAddress}")));
            Assert.Single(assets);
            Assert.All(hosts, h => Assert.Equal(assets[0].Id, h.AssetId));
        }

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
    }
}
