using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Infrastructure.Queries;
using Weles.Infrastructure.Settings;
using Weles.Tests.Support;

namespace Weles.Tests.Infrastructure;

public class SettingsServiceTests
{
    [Fact]
    public async Task Set_then_get_returns_value_and_overwrites_existing()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        var settings = new SettingsService(testDb, TimeProvider.System);

        Assert.Null(await settings.GetAsync("ui.theme"));
        await settings.SetAsync("ui.theme", "light");
        await settings.SetAsync("ui.theme", "dark");

        Assert.Equal("dark", await settings.GetAsync("ui.theme"));
    }
}

public class DashboardQueriesTests
{
    [Fact]
    public async Task Empty_database_reports_no_scans_and_zero_counts()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        var summary = await new DashboardQueries(testDb).GetSummaryAsync();

        Assert.False(summary.HasAnyScan);
        Assert.Null(summary.LastScan);
        Assert.Null(summary.SecurityPostureScore);
        Assert.Equal(0, summary.AssetCount);
        Assert.Null(summary.VulnerabilityDatabaseUpdatedAt);
    }

    [Fact]
    public async Task Summary_is_computed_from_the_latest_completed_scan()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        await using (var db = testDb.CreateDbContext())
        {
            var target = TestData.ApprovedTarget();
            var oldAsset = new Asset { DisplayName = "router", FirstSeenAt = TestData.Now.AddDays(-7), LastSeenAt = TestData.Now };
            var newAsset = new Asset { DisplayName = "camera", FirstSeenAt = TestData.Now.AddMinutes(1), LastSeenAt = TestData.Now };

            var previous = TestData.CompletedScan(target, TestData.Now.AddDays(-7));
            previous.Hosts.Add(new DiscoveredHost { IpAddress = "10.0.0.1", Asset = oldAsset, DiscoveredAt = previous.StartedAt!.Value, Ports = [new DiscoveredPort { Port = 80, State = PortState.Open }] });

            var latest = TestData.CompletedScan(target, TestData.Now);
            latest.HostsAlive = 2;
            latest.Hosts.Add(new DiscoveredHost
            {
                IpAddress = "10.0.0.1", Asset = oldAsset, DiscoveredAt = TestData.Now,
                Ports = [new DiscoveredPort { Port = 80, State = PortState.Open }, new DiscoveredPort { Port = 443, State = PortState.Open }, new DiscoveredPort { Port = 23, State = PortState.Closed }]
            });
            latest.Hosts.Add(new DiscoveredHost { IpAddress = "10.0.0.9", Asset = newAsset, DiscoveredAt = TestData.Now, Ports = [new DiscoveredPort { Port = 554, State = PortState.Open }] });
            latest.Findings.Add(new RiskFinding { Asset = newAsset, RuleId = "R1", Title = "t", Category = "c", Level = RiskLevel.Critical, CreatedAt = TestData.Now });
            latest.Findings.Add(new RiskFinding { Asset = oldAsset, RuleId = "R2", Title = "t", Category = "c", Level = RiskLevel.Low, CreatedAt = TestData.Now });
            latest.RiskScores.Add(new RiskScore { Score = 72, Level = RiskLevel.Medium, BreakdownJson = "[]", CalculatedAt = TestData.Now });

            var running = new Scan { ScanTarget = target, Status = ScanStatus.Running, PortSpecification = "top100", CreatedAt = TestData.Now.AddHours(1), StartedAt = TestData.Now.AddHours(1) };

            db.Scans.AddRange(previous, latest, running);
            await db.SaveChangesAsync();
        }

        var summary = await new DashboardQueries(testDb).GetSummaryAsync();

        Assert.True(summary.HasAnyScan);
        Assert.Equal(2, summary.CompletedScanCount);
        Assert.Equal(2, summary.AssetCount);
        Assert.Equal(3, summary.ActiveServiceCount);
        Assert.Equal(1, summary.CriticalFindingCount);
        Assert.Equal(1, summary.NewAssetsSinceLastScan);
        Assert.Equal(72, summary.SecurityPostureScore);
        Assert.Equal(2, summary.LastScan!.HostsAlive);
    }
}
