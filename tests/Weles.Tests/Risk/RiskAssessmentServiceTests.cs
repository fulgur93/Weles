using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Rules;
using Weles.Infrastructure.Queries;
using Weles.Infrastructure.Risk;
using Weles.Infrastructure.Scanning;
using Weles.Infrastructure.Settings;
using Weles.Tests.Support;

namespace Weles.Tests.Risk;

/// <summary>Scan → configuration findings → device scores → Security Posture Score, on a real SQLite database.</summary>
public class RiskAssessmentServiceTests
{
    private static HostScanResult Host(string ip, string mac, bool gateway, params (int Port, string Service, Dictionary<string, string> Extra)[] ports) => new(
        System.Net.IPAddress.Parse(ip), DiscoveryMethod.TcpConnect, null, 64, null, mac, null, gateway,
        new HostClassification(gateway ? AssetType.Router : AssetType.LinuxHost, "Linux", 60, ["test"]),
        ports.Select(p => new PortScanResult(p.Port, "syn-ack", new ServiceProbeResult(
            new Weles.Core.Models.ServiceIdentification { ServiceName = p.Service, Method = "banner", Confidence = 90, Extra = p.Extra }, null))).ToList());

    private static async Task<int> ScanAsync(TestDatabase testDb, ScanTarget target, DateTime started)
    {
        await using var db = testDb.CreateDbContext();
        db.Attach(target);
        var scan = new Scan
        {
            ScanTarget = target, Status = ScanStatus.Completed, PortSpecification = "quick", CreatedAt = started, StartedAt = started, CompletedAt = started.AddMinutes(1),
            ScopeSnapshot = JsonSerializer.Serialize(new[] { new { Value = "10.0.0.0/24", IsExclusion = false } })
        };
        db.Scans.Add(scan);
        await db.SaveChangesAsync();
        return scan.Id;
    }

    [Fact]
    public async Task Scan_produces_findings_scores_posture_and_follows_changes()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        ScanTarget target;
        await using (var db = testDb.CreateDbContext())
        {
            target = TestData.ApprovedTarget();
            db.ScanTargets.Add(target);
            await db.SaveChangesAsync();
        }

        var writer = new ScanResultWriter(testDb, TimeProvider.System);
        var risk = new RiskAssessmentService(testDb, new SettingsService(testDb, TimeProvider.System), TimeProvider.System, NullLogger<RiskAssessmentService>.Instance);
        var queries = new RiskQueries(testDb);

        var first = await ScanAsync(testDb, target, TestData.Now.AddDays(-1));
        await writer.SaveHostAsync(first, Host("10.0.0.1", "aa:00:00:00:00:01", true, (23, "telnet", []), (80, "http", new() { ["http.upnp"] = "1" })));
        await writer.SaveHostAsync(first, Host("10.0.0.5", "aa:00:00:00:00:05", false, (6379, "redis", new() { ["redis.auth"] = "none" })));
        await writer.SaveHostAsync(first, Host("10.0.0.9", "aa:00:00:00:00:09", false));
        var summary = await risk.RefreshScanAsync(first);
        Assert.Equal(3, summary.Assets);
        Assert.Equal(3, summary.NewFindings);

        var overview = await queries.OverviewAsync();
        // Router: Telnet 70 + 10% of UPnP + gateway 8 + UPnP on a router 5 = 85.5; Redis without auth: 85.
        Assert.Equal(["10.0.0.1", "10.0.0.5", "10.0.0.9"], overview.Assets.Select(a => a.Ip));
        var router = overview.Assets[0];
        Assert.Equal((85.5, RiskLevel.Critical), (router.Score, router.Level));
        Assert.Equal((85, "Redis bez uwierzytelniania"), (overview.Assets[1].Score, overview.Assets[1].TopIssue));
        // Fix order: the Redis issue itself weighs more than Telnet, even with the router's context (70 + 8 + 5 = 83).
        Assert.Equal("Redis bez uwierzytelniania", overview.Priorities[0].Issue.Title);
        Assert.Equal((83, "Telnet – logowanie bez szyfrowania"), (overview.Priorities[1].Priority, overview.Priorities[1].Issue.Title));
        Assert.Single(overview.Networks);
        Assert.Equal(summary.Posture, overview.Networks[0].Latest.Score);
        Assert.True(summary.Posture < 30);

        await using (var db = testDb.CreateDbContext())
        {
            Assert.Equal(RiskLevel.Critical, (await db.Assets.SingleAsync(a => a.PrimaryIpAddress == "10.0.0.5")).CurrentRiskLevel);
            var telnet = await db.RiskFindings.SingleAsync(f => f.RuleId == "TELNET");
            Assert.Equal((23, FindingStatus.Open), (telnet.Port!.Value, telnet.Status));
            Assert.Contains("T1040", telnet.AttackTechniques);
        }

        // The user accepts the Telnet risk; the next scan shows Redis fixed – findings follow, history is kept.
        var telnetId = (await queries.AssetAsync(router.AssetId))!.Findings.Single(f => f.RuleId == "TELNET").Id;
        Assert.NotNull(await queries.SetFindingStatusAsync(telnetId, FindingStatus.Accepted));

        var second = await ScanAsync(testDb, target, TestData.Now);
        await writer.SaveHostAsync(second, Host("10.0.0.1", "aa:00:00:00:00:01", true, (23, "telnet", []), (80, "http", new() { ["http.upnp"] = "1" })));
        await writer.SaveHostAsync(second, Host("10.0.0.5", "aa:00:00:00:00:05", false, (6379, "redis", new() { ["redis.auth"] = "required" })));
        await writer.SaveHostAsync(second, Host("10.0.0.9", "aa:00:00:00:00:09", false));
        var after = await risk.RefreshScanAsync(second);
        Assert.Equal(1, after.ResolvedFindings);
        Assert.True(after.Posture > summary.Posture);

        await using (var db = testDb.CreateDbContext())
        {
            Assert.Equal(FindingStatus.Resolved, (await db.RiskFindings.SingleAsync(f => f.RuleId == "REDIS-NOAUTH")).Status);
            Assert.Equal(FindingStatus.Accepted, (await db.RiskFindings.SingleAsync(f => f.RuleId == "TELNET")).Status);
            Assert.Equal(FindingStatus.Open, (await db.RiskFindings.SingleAsync(f => f.RuleId == "DB-EXPOSED")).Status);
        }

        var routerDetail = (await queries.AssetAsync(router.AssetId))!;   // router.AssetId from the first overview
        Assert.DoesNotContain(routerDetail.Result.Issues, i => i.RuleId == "TELNET");
        Assert.Contains(routerDetail.Result.Factors, f => f.Kind == "accepted");
        Assert.Equal(2, routerDetail.History.Count);

        var trend = (await queries.OverviewAsync()).Trend;
        Assert.Equal(2, trend.Count);
        Assert.True(trend[1].Score > trend[0].Score);
    }
}
