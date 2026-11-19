using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Risk;
using Weles.Core.Rules;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Queries;
using Weles.Infrastructure.Settings;

namespace Weles.Infrastructure.Risk;

public sealed record RiskSummary(int Assets, double? Posture, int Critical, int High, int NewFindings, int ResolvedFindings);

/// <summary>Posture breakdown stored with the network score (RiskScore with AssetId = null).</summary>
public sealed record PostureBreakdown(IReadOnlyList<RiskFactor> Factors, IReadOnlyDictionary<RiskLevel, int> AssetsByLevel, string? Network);

/// <summary>
/// Runs the risk engine after every scan (and after the vulnerability database changes): configuration findings with
/// their lifecycle, a score per device and the Security Posture Score of the scanned network – stored per scan, so the
/// trend over time is real history, not a recalculation.
/// </summary>
public sealed class RiskAssessmentService(IDbContextFactory<WelesDbContext> contextFactory, SettingsService settings, TimeProvider timeProvider, ILogger<RiskAssessmentService> logger)
{
    /// <summary>Bump when rules or weights change – the latest scans are re-assessed on the next start.</summary>
    public const int EngineVersion = 2;
    public const string EngineVersionKey = "risk.engineVersion";

    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly SemaphoreSlim _lock = new(1, 1);

    /// <summary>Re-assesses the latest completed scan of every network when the engine version changed.</summary>
    public async Task InitializeAsync(bool force, CancellationToken ct = default)
    {
        if (!force && await settings.GetAsync(EngineVersionKey, ct) == EngineVersion.ToString()) return;
        await RefreshLatestAsync(ct);
        await settings.SetAsync(EngineVersionKey, EngineVersion.ToString(), ct);
    }

    /// <summary>Latest completed scan per network – after a vulnerability database update the current state changes.</summary>
    public async Task RefreshLatestAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var scans = await db.Scans.AsNoTracking().Where(s => s.Status == ScanStatus.Completed && s.StartedAt != null)
            .Select(s => new { s.Id, s.StartedAt, s.NetworkFingerprint }).ToListAsync(ct);
        foreach (var latest in scans.GroupBy(s => s.NetworkFingerprint).Select(g => g.OrderByDescending(s => s.StartedAt).First()))
        {
            await RefreshScanAsync(latest.Id, ct);
        }
    }

    public async Task<RiskSummary> RefreshScanAsync(int scanId, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            return await AssessAsync(scanId, ct);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<RiskSummary> AssessAsync(int scanId, CancellationToken ct)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var scan = await db.Scans.AsNoTracking().SingleOrDefaultAsync(s => s.Id == scanId, ct);
        if (scan is null) return new RiskSummary(0, null, 0, 0, 0, 0);

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var assetIds = await db.DiscoveredHosts.Where(h => h.ScanId == scanId && h.AssetId != null).Select(h => h.AssetId!.Value).Distinct().ToListAsync(ct);
        var results = new List<(string Name, double Score)>();
        int added = 0, resolved = 0;

        foreach (var assetId in assetIds)
        {
            var (name, result, n, r) = await AssessAssetAsync(db, assetId, scanId, now, ct);
            if (result is null) continue;
            results.Add((name, result.Score));
            added += n;
            resolved += r;
        }

        var posture = Invariant(() => RiskEngine.Posture(results));
        var network = await db.NetworkSegments.AsNoTracking()
            .Where(s => scan.NetworkFingerprint != null && s.GatewayMac == scan.NetworkFingerprint)
            .Select(s => NetworkNaming.Label(s.Cidr, s.Name, s.GatewayVendor, s.GatewayMac)).FirstOrDefaultAsync(ct);
        await UpsertScoreAsync(db, scanId, null, posture.Score, RiskEngine.LevelOf(100 - posture.Score),
            JsonSerializer.Serialize(new PostureBreakdown(posture.Factors, posture.AssetsByLevel, network), Json), now, ct);
        await db.SaveChangesAsync(ct);

        var summary = new RiskSummary(results.Count, results.Count == 0 ? null : posture.Score,
            posture.AssetsByLevel[RiskLevel.Critical], posture.AssetsByLevel[RiskLevel.High], added, resolved);
        logger.LogInformation("Risk assessment of scan {ScanId}: {Assets} assets, posture {Posture}", scanId, summary.Assets, summary.Posture);
        return summary;
    }

    private async Task<(string Name, AssetRiskResult? Result, int Added, int Resolved)> AssessAssetAsync(WelesDbContext db, int assetId, int scanId, DateTime now, CancellationToken ct)
    {
        var asset = await db.Assets.SingleOrDefaultAsync(a => a.Id == assetId, ct);
        if (asset is null) return ("", null, 0, 0);

        var hosts = await db.DiscoveredHosts.AsNoTracking().AsSplitQuery()
            .Where(h => h.AssetId == assetId && (h.Scan!.Status == ScanStatus.Completed || h.Scan.Status == ScanStatus.Cancelled))
            .Include(h => h.Scan)
            .Include(h => h.Ports).ThenInclude(p => p.Service).ThenInclude(s => s!.Certificates)
            .OrderBy(h => h.DiscoveredAt)
            .ToListAsync(ct);
        var history = ObservationComparer.Replay(hosts.Select(h => new PortObservation(h, AssetQueries.CheckedPorts(h.Scan!.PortSpecification))).ToList());
        var latest = hosts.LastOrDefault();

        // Configuration rules over the current ports.
        var detected = new List<ConfigFinding>();
        foreach (var port in history.CurrentPorts)
        {
            var svc = port.Service;
            var cert = svc?.Certificates.FirstOrDefault();
            var facts = new ServiceFacts(port.Port, svc?.ServiceName, svc?.Product, svc?.Confidence ?? 0, svc?.DetectionMethod, svc?.IsTls ?? false, Extra(svc?.ExtraInfoJson),
                cert is null ? null : new CertificateFacts(cert.NotAfter, cert.IsSelfSigned, cert.HostnameMatches, cert.KeySize, cert.KeyAlgorithm));
            detected.AddRange(Invariant(() => RiskRules.Evaluate(facts, now).ToList()));
        }

        detected = detected.DistinctBy(f => (f.Rule.Id, f.Port)).ToList();
        var (added, resolved, accepted) = await SyncFindingsAsync(db, asset.Id, scanId, detected, now, ct);
        var active = detected.Where(f => !accepted.Contains((f.Rule.Id, f.Port))).ToList();

        var vulns = await db.AssetVulnerabilities.AsNoTracking().Where(v => v.AssetId == assetId && v.Status != FindingStatus.Resolved)
            .Select(v => new { v.Status, v.Vulnerability!.CveId, v.Vulnerability.CvssScore, v.Vulnerability.EpssScore, v.Vulnerability.IsKnownExploited, v.MatchStatus, v.Port, v.Product, v.DetectedVersion, v.Vulnerability.PublishedAt })
            .ToListAsync(ct);
        var openVulns = vulns.Where(v => v.Status == FindingStatus.Open)
            .Select(v => new VulnerabilityFacts(v.CveId, v.CvssScore, v.EpssScore, v.IsKnownExploited, v.MatchStatus, v.Port, v.Product, v.DetectedVersion, v.PublishedAt)).ToList();

        var newPorts = history.Changes.Count > 1
            ? history.Changes[^1].Where(c => c.Kind == AssetChangeKind.PortOpened && c.Port is not null).Select(c => c.Port!.Value).ToList()
            : [];
        var isPublic = IPAddress.TryParse(asset.PrimaryIpAddress, out var ip) && AddressClassifier.IsPublic(ip);

        var input = new AssetRiskInput(asset.EffectiveType, asset.Criticality, latest?.IsGateway ?? false, isPublic,
            history.CurrentPorts.Count, active, openVulns, newPorts, accepted.Count + vulns.Count(v => v.Status == FindingStatus.Accepted));
        var result = Invariant(() => RiskEngine.ScoreAsset(input, now));

        asset.CurrentRiskScore = result.Score;
        asset.CurrentRiskLevel = result.Level;
        await UpsertScoreAsync(db, scanId, asset.Id, result.Score, result.Level, JsonSerializer.Serialize(result, Json), now, ct);
        await db.SaveChangesAsync(ct);
        return (asset.CustomName ?? asset.DisplayName, result, added, resolved);
    }

    /// <summary>Open/resolve/reopen findings like vulnerability matches; the user's "accepted" decision is kept.</summary>
    private static async Task<(int Added, int Resolved, HashSet<(string, int?)> Accepted)> SyncFindingsAsync(WelesDbContext db, int assetId, int scanId, IReadOnlyList<ConfigFinding> detected, DateTime now, CancellationToken ct)
    {
        var existing = await db.RiskFindings.Where(f => f.AssetId == assetId).ToListAsync(ct);
        int added = 0, resolved = 0;
        foreach (var d in detected)
        {
            var f = existing.FirstOrDefault(e => e.RuleId == d.Rule.Id && e.Port == d.Port);
            if (f is null)
            {
                f = new RiskFinding { AssetId = assetId, RuleId = d.Rule.Id, Title = d.Rule.Title, Category = d.Rule.Category, Port = d.Port, CreatedAt = now, Status = FindingStatus.Open };
                db.RiskFindings.Add(f);
                existing.Add(f);
                added++;
            }
            else if (f.Status == FindingStatus.Resolved)
            {
                f.Status = FindingStatus.Open;
                f.ResolvedAt = null;
            }

            f.ScanId = scanId;
            f.Title = d.Rule.Title;
            f.Category = d.Rule.Category;
            f.Score = d.Rule.BaseScore;
            f.Level = RiskEngine.LevelOf(d.Rule.BaseScore);
            f.Evidence = Truncate(d.Evidence, 4000);
            f.Recommendation = Truncate(d.Rule.Recommendation, 4000);
            f.Confidence = d.Confidence;
            f.AttackTechniques = string.Join(',', d.Rule.AttackTechniques);
            f.LastDetectedAt = now;
        }

        foreach (var f in existing.Where(f => f.Status == FindingStatus.Open && !detected.Any(d => d.Rule.Id == f.RuleId && d.Port == f.Port)))
        {
            f.Status = FindingStatus.Resolved;
            f.ResolvedAt = now;
            f.ScanId = scanId;
            resolved++;
        }

        var accepted = existing.Where(f => f.Status == FindingStatus.Accepted).Select(f => (f.RuleId, f.Port)).ToHashSet();
        return (added, resolved, accepted);
    }

    private static async Task UpsertScoreAsync(WelesDbContext db, int scanId, int? assetId, double score, RiskLevel level, string breakdown, DateTime now, CancellationToken ct)
    {
        var row = await db.RiskScores.FirstOrDefaultAsync(r => r.ScanId == scanId && r.AssetId == assetId, ct);
        if (row is null)
        {
            row = new RiskScore { ScanId = scanId, AssetId = assetId, BreakdownJson = "" };
            db.RiskScores.Add(row);
        }

        row.Score = score;
        row.Level = level;
        row.BreakdownJson = breakdown;
        row.CalculatedAt = now;
    }

    /// <summary>
    /// Stored explanations use a culture-independent number format ("CVSS 9.8", as NVD writes it) – they are shown in
    /// both UI languages, and a background thread's culture must not decide the decimal separator.
    /// </summary>
    private static T Invariant<T>(Func<T> compute)
    {
        var culture = System.Globalization.CultureInfo.CurrentCulture;
        System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.InvariantCulture;
        try
        {
            return compute();
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = culture;
        }
    }

    private static Dictionary<string, string> Extra(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static string? Truncate(string? value, int max) => value is null || value.Length <= max ? value : value[..max];
}
