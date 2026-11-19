using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Risk;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Risk;

namespace Weles.Infrastructure.Queries;

public sealed record PosturePoint(int ScanId, DateTime At, double Score, string? Network, string? Fingerprint);

public sealed record NetworkPosture(PosturePoint Latest, double? Previous, PostureBreakdown Breakdown);

public sealed record AssetRiskRow(int AssetId, string Name, string? Ip, AssetType Type, AssetCriticality Criticality, double Score, RiskLevel Level, int Issues, int KnownExploited, string? TopIssue, int ScanId, DateTime AssessedAt);

/// <summary>
/// One thing to fix, in priority order. <see cref="Priority"/> = the issue's own score + the device's context (role,
/// exposure, age, changes, criticality) – the same context that raised the device score.
/// </summary>
public sealed record RemediationItem(int AssetId, string AssetName, string? AssetIp, RiskIssue Issue, double Priority, RiskLevel Level, IReadOnlyList<RiskFactor> Context);

public sealed record RiskOverview(
    IReadOnlyList<NetworkPosture> Networks,
    IReadOnlyList<PosturePoint> Trend,
    IReadOnlyList<AssetRiskRow> Assets,
    IReadOnlyList<RemediationItem> Priorities);

public sealed record AssetRiskDetail(AssetRiskResult Result, int ScanId, DateTime AssessedAt, IReadOnlyList<RiskFinding> Findings, IReadOnlyList<(int ScanId, DateTime At, double Score)> History);

public sealed class RiskQueries(IDbContextFactory<WelesDbContext> contextFactory)
{
    private static readonly HashSet<string> ContextKinds = ["role", "exposure", "services", "age", "changes"];

    public async Task<RiskOverview> OverviewAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var postures = await db.RiskScores.AsNoTracking().Where(r => r.AssetId == null && r.Scan!.Status == ScanStatus.Completed)
            .Select(r => new { r.ScanId, At = r.Scan!.StartedAt ?? r.Scan.CreatedAt, r.Score, r.BreakdownJson, r.Scan.NetworkFingerprint })
            .ToListAsync(ct);
        var trend = postures.OrderBy(p => p.At)
            .Select(p => new PosturePoint(p.ScanId, p.At, p.Score, Breakdown(p.BreakdownJson)?.Network, p.NetworkFingerprint)).ToList();

        var networks = postures.GroupBy(p => p.NetworkFingerprint)
            .Select(g =>
            {
                var ordered = g.OrderByDescending(p => p.At).ToList();
                var latest = ordered[0];
                return new NetworkPosture(new PosturePoint(latest.ScanId, latest.At, latest.Score, Breakdown(latest.BreakdownJson)?.Network, latest.NetworkFingerprint),
                    ordered.Count > 1 ? ordered[1].Score : null, Breakdown(latest.BreakdownJson) ?? new PostureBreakdown([], new Dictionary<RiskLevel, int>(), null));
            })
            .OrderByDescending(n => n.Latest.At).ToList();

        var latestScores = await LatestAssetScoresAsync(db, ct);
        var assets = latestScores.Select(x => new AssetRiskRow(x.Asset.Id, x.Asset.CustomName ?? x.Asset.DisplayName, x.Asset.PrimaryIpAddress, x.Asset.EffectiveType, x.Asset.Criticality,
                x.Result.Score, x.Result.Level, x.Result.Issues.Count, x.Result.Issues.Sum(i => i.KnownExploited), x.Result.Issues.FirstOrDefault()?.Title, x.ScanId, x.At))
            .OrderByDescending(a => a.Score).ThenBy(a => a.Name, StringComparer.Ordinal).ToList();

        return new RiskOverview(networks, trend, assets, Prioritize(latestScores.Select(x => (x.Asset, x.Result))));
    }

    /// <summary>Top remediation items across the inventory (dashboard).</summary>
    public async Task<IReadOnlyList<RemediationItem>> PrioritiesAsync(int take, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        return Prioritize((await LatestAssetScoresAsync(db, ct)).Select(x => (x.Asset, x.Result))).Take(take).ToList();
    }

    public async Task<AssetRiskDetail?> AssetAsync(int assetId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var rows = await db.RiskScores.AsNoTracking().Where(r => r.AssetId == assetId)
            .Select(r => new { r.ScanId, At = r.Scan!.StartedAt ?? r.Scan.CreatedAt, r.Score, r.BreakdownJson }).ToListAsync(ct);
        if (rows.Count == 0) return null;
        var latest = rows.OrderByDescending(r => r.At).First();
        var result = Result(latest.BreakdownJson);
        if (result is null) return null;
        var findings = await db.RiskFindings.AsNoTracking().Where(f => f.AssetId == assetId)
            .OrderBy(f => f.Status).ThenByDescending(f => f.Score).ToListAsync(ct);
        return new AssetRiskDetail(result, latest.ScanId, latest.At, findings, rows.OrderBy(r => r.At).Select(r => (r.ScanId, r.At, r.Score)).ToList());
    }

    /// <summary>Accept a configuration risk (or reopen it). Resolved findings are managed by scans only.</summary>
    public async Task<int?> SetFindingStatusAsync(int findingId, FindingStatus status, CancellationToken ct = default)
    {
        if (status == FindingStatus.Resolved) return null;
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var f = await db.RiskFindings.SingleOrDefaultAsync(x => x.Id == findingId, ct);
        if (f is null || f.Status == FindingStatus.Resolved) return null;
        f.Status = status;
        await db.SaveChangesAsync(ct);
        return f.AssetId;
    }

    /// <summary>Latest scan in which the asset was assessed – re-assess it after the user changes a decision.</summary>
    public async Task<int?> LatestScanOfAssetAsync(int assetId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        return await db.RiskScores.Where(r => r.AssetId == assetId).OrderByDescending(r => r.Scan!.StartedAt).Select(r => (int?)r.ScanId).FirstOrDefaultAsync(ct);
    }

    /// <summary>Number of Critical issues in the latest assessment of the scan's devices.</summary>
    internal static async Task<int> CriticalIssuesAsync(WelesDbContext db, int scanId, CancellationToken ct)
    {
        var rows = await db.RiskScores.AsNoTracking().Where(r => r.ScanId == scanId && r.AssetId != null).Select(r => r.BreakdownJson).ToListAsync(ct);
        return rows.Select(Result).Where(r => r is not null).Sum(r => r!.Issues.Count(i => i.Level == RiskLevel.Critical));
    }

    internal static IReadOnlyList<RemediationItem> Prioritize(IEnumerable<(Asset Asset, AssetRiskResult Result)> assessed)
    {
        var items = new List<RemediationItem>();
        foreach (var (asset, result) in assessed)
        {
            var context = result.Factors.Where(f => ContextKinds.Contains(f.Kind) && f.Points != 0).ToList();
            var bonus = context.Sum(f => f.Points);
            var multiplier = RiskEngine.CriticalityMultiplier(asset.Criticality);
            foreach (var issue in result.Issues)
            {
                var priority = Math.Round(Math.Clamp(issue.Score * multiplier + bonus, 0, 100), 1);
                var ctx = multiplier == 1.0 ? context : [.. context, new RiskFactor("criticality", $"krytyczność urządzenia × {multiplier:0.##}", Math.Round(issue.Score * (multiplier - 1), 1))];
                items.Add(new RemediationItem(asset.Id, asset.CustomName ?? asset.DisplayName, asset.PrimaryIpAddress, issue, priority, RiskEngine.LevelOf(priority), ctx));
            }
        }

        return items.OrderByDescending(i => i.Priority).ThenByDescending(i => i.Issue.KnownExploited).ThenBy(i => i.AssetName, StringComparer.Ordinal).ToList();
    }

    private static async Task<List<(Asset Asset, AssetRiskResult Result, int ScanId, DateTime At)>> LatestAssetScoresAsync(WelesDbContext db, CancellationToken ct)
    {
        var rows = await db.RiskScores.AsNoTracking().Where(r => r.AssetId != null)
            .Select(r => new { AssetId = r.AssetId!.Value, r.ScanId, At = r.Scan!.StartedAt ?? r.Scan.CreatedAt, r.BreakdownJson }).ToListAsync(ct);
        var latest = rows.GroupBy(r => r.AssetId).Select(g => g.OrderByDescending(r => r.At).First()).ToList();
        var ids = latest.Select(r => r.AssetId).ToList();
        var assets = await db.Assets.AsNoTracking().Where(a => ids.Contains(a.Id)).ToDictionaryAsync(a => a.Id, ct);
        return latest.Where(r => assets.ContainsKey(r.AssetId) && Result(r.BreakdownJson) is not null)
            .Select(r => (assets[r.AssetId], Result(r.BreakdownJson)!, r.ScanId, r.At)).ToList();
    }

    internal static AssetRiskResult? Result(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<AssetRiskResult>(json, RiskAssessmentService.Json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static PostureBreakdown? Breakdown(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<PostureBreakdown>(json, RiskAssessmentService.Json);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
