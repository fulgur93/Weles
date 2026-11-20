using Microsoft.EntityFrameworkCore;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Database;

namespace Weles.Infrastructure.Queries;

public sealed record ScanRef(int Id, DateTime At, string TargetName, string PortSpecification, string? Network);

public sealed record DeviceRef(int AssetId, string Name, string? Ip);

public sealed record DeviceChanges(DeviceRef Device, IReadOnlyList<AssetChange> Changes);

public sealed record VulnerabilityChange(DeviceRef Device, string CveId, double? CvssScore, bool IsKnownExploited, VulnerabilityMatchStatus MatchStatus, string? Product, string? Version);

public sealed record RiskChange(DeviceRef Device, double? Before, double After, RiskLevel Level);

/// <summary>
/// Everything that changed between two scans of the same network. Devices count as gone only when the newer scan
/// covered their address; ports only when both scans checked them (a quick scan after a standard one closes nothing).
/// </summary>
public sealed record ScanComparison(
    ScanRef Previous,
    ScanRef Current,
    bool SameNetwork,
    IReadOnlyList<DeviceRef> NewDevices,
    IReadOnlyList<DeviceRef> ReturnedDevices,
    IReadOnlyList<DeviceRef> MissingDevices,
    IReadOnlyList<DeviceChanges> Changed,
    IReadOnlyList<VulnerabilityChange> NewVulnerabilities,
    IReadOnlyList<VulnerabilityChange> ResolvedVulnerabilities,
    IReadOnlyList<RiskChange> RiskChanges,
    double? PostureBefore,
    double? PostureAfter)
{
    public int Count(AssetChangeKind kind) => Changed.Sum(c => c.Changes.Count(x => x.Kind == kind));

    public int Total => NewDevices.Count + ReturnedDevices.Count + MissingDevices.Count + Changed.Sum(c => c.Changes.Count)
                        + NewVulnerabilities.Count + ResolvedVulnerabilities.Count + RiskChanges.Count;
}

/// <summary>One step of the change history: a scan compared with the previous scan of its network.</summary>
public sealed record TimelineEntry(ScanRef Scan, int? PreviousScanId, int NewDevices, int MissingDevices, int PortsOpened, int PortsClosed, int VersionChanges,
    int NewVulnerabilities, int ResolvedVulnerabilities, double? Posture, double? PostureBefore);

public sealed class MonitoringQueries(IDbContextFactory<WelesDbContext> contextFactory)
{
    /// <summary>Significant risk movement shown in the comparison (points on the 0–100 scale).</summary>
    public const double RiskDelta = 5;

    /// <summary>Time after a scan in which vulnerability matching and risk assessment store their results.</summary>
    public static readonly TimeSpan MatchingWindow = TimeSpan.FromMinutes(2);

    /// <summary>Readable names of networks by gateway fingerprint ("192.168.0.0/24 · TP-LINK c0:4a:…").</summary>
    public async Task<IReadOnlyDictionary<string, string>> NetworkLabelsAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var segments = await db.NetworkSegments.AsNoTracking().Where(s => s.GatewayMac != null).ToListAsync(ct);
        return segments.GroupBy(s => s.GatewayMac!).ToDictionary(g => g.Key, g => NetworkNaming.Label(g.First().Cidr, g.First().Name, g.First().GatewayVendor, g.First().GatewayMac));
    }

    /// <summary>Completed scans, newest first – choices for the comparison.</summary>
    public async Task<IReadOnlyList<ScanRef>> ScansAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        return await Project(Completed(db).OrderByDescending(s => s.StartedAt)).ToListAsync(ct);
    }

    /// <summary>The scan before <paramref name="scanId"/> on the same network (null for the first one).</summary>
    public async Task<int?> PreviousOnSameNetworkAsync(int scanId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var scan = await db.Scans.AsNoTracking().Where(s => s.Id == scanId).Select(s => new { s.StartedAt, s.NetworkFingerprint }).SingleOrDefaultAsync(ct);
        if (scan is null) return null;
        return await db.Scans.AsNoTracking()
            .Where(s => s.Status == ScanStatus.Completed && s.StartedAt < scan.StartedAt && s.NetworkFingerprint == scan.NetworkFingerprint)
            .OrderByDescending(s => s.StartedAt).Select(s => (int?)s.Id).FirstOrDefaultAsync(ct);
    }

    /// <summary>"What changed since the last audit?" – the latest completed scan against the previous one of its network.</summary>
    public async Task<ScanComparison?> LatestAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var latest = await db.Scans.AsNoTracking().Where(s => s.Status == ScanStatus.Completed).OrderByDescending(s => s.StartedAt).Select(s => (int?)s.Id).FirstOrDefaultAsync(ct);
        if (latest is null || await PreviousOnSameNetworkAsync(latest.Value, ct) is not { } previous) return null;
        return await CompareAsync(previous, latest.Value, ct);
    }

    public async Task<ScanComparison?> CompareAsync(int previousScanId, int currentScanId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var refs = await Project(Completed(db).Where(s => s.Id == previousScanId || s.Id == currentScanId)).ToListAsync(ct);
        var prev = refs.SingleOrDefault(s => s.Id == previousScanId);
        var cur = refs.SingleOrDefault(s => s.Id == currentScanId);
        if (prev is null || cur is null) return null;
        if (prev.At > cur.At) (prev, cur) = (cur, prev);

        var scans = await db.Scans.AsNoTracking().Where(s => s.Id == prev.Id || s.Id == cur.Id)
            .Select(s => new { s.Id, s.PortSpecification, s.ScopeSnapshot, s.NetworkFingerprint, s.CompletedAt }).ToDictionaryAsync(s => s.Id, ct);
        var hosts = await db.DiscoveredHosts.AsNoTracking().AsSplitQuery()
            .Where(h => (h.ScanId == prev.Id || h.ScanId == cur.Id) && h.AssetId != null)
            .Include(h => h.Ports).ThenInclude(p => p.Service).ThenInclude(s => s!.Certificates)
            .ToListAsync(ct);
        var assetIds = hosts.Select(h => h.AssetId!.Value).Distinct().ToList();
        var assets = await db.Assets.AsNoTracking().Where(a => assetIds.Contains(a.Id)).ToDictionaryAsync(a => a.Id, ct);
        DeviceRef Ref(int id, string? ip = null) => assets.TryGetValue(id, out var a) ? new DeviceRef(id, a.CustomName ?? a.DisplayName, ip ?? a.PrimaryIpAddress) : new DeviceRef(id, "#" + id, ip);

        var before = hosts.Where(h => h.ScanId == prev.Id).GroupBy(h => h.AssetId!.Value).ToDictionary(g => g.Key, g => Merge(g));
        var after = hosts.Where(h => h.ScanId == cur.Id).GroupBy(h => h.AssetId!.Value).ToDictionary(g => g.Key, g => Merge(g));

        var firstScan = await db.DiscoveredHosts.AsNoTracking().Where(h => h.AssetId != null && after.Keys.Contains(h.AssetId.Value))
            .GroupBy(h => h.AssetId!.Value).Select(g => new { Id = g.Key, First = g.Min(h => h.ScanId) }).ToDictionaryAsync(x => x.Id, x => x.First, ct);
        var appeared = after.Keys.Except(before.Keys).ToList();
        var newDevices = appeared.Where(id => firstScan.GetValueOrDefault(id) == cur.Id).Select(id => Ref(id, after[id].IpAddress)).ToList();
        var returned = appeared.Where(id => firstScan.GetValueOrDefault(id) != cur.Id).Select(id => Ref(id, after[id].IpAddress)).ToList();

        var coverage = ScopeCoverage.FromSnapshot(scans[cur.Id].ScopeSnapshot);
        var missing = before.Keys.Except(after.Keys).Where(id => coverage.Covers(before[id].IpAddress)).Select(id => Ref(id, before[id].IpAddress)).ToList();

        var prevChecked = AssetQueries.CheckedPorts(scans[prev.Id].PortSpecification);
        var curChecked = AssetQueries.CheckedPorts(scans[cur.Id].PortSpecification);
        var changed = new List<DeviceChanges>();
        foreach (var id in before.Keys.Intersect(after.Keys))
        {
            var history = ObservationComparer.Replay([new PortObservation(before[id], prevChecked), new PortObservation(after[id], curChecked)]);
            if (history.Changes[1].Count > 0) changed.Add(new DeviceChanges(Ref(id, after[id].IpAddress), history.Changes[1]));
        }

        // Matching runs right after each scan (seconds): a finding stored up to MatchingWindow after a scan belongs to that
        // scan, so the window is shifted by it at both ends – otherwise one finding would count for two scans.
        var from = (scans[prev.Id].CompletedAt ?? prev.At) + MatchingWindow;
        var to = (scans[cur.Id].CompletedAt ?? cur.At) + MatchingWindow;
        var vulns = await db.AssetVulnerabilities.AsNoTracking()
            .Where(v => assetIds.Contains(v.AssetId) && ((v.FirstDetectedAt > from && v.FirstDetectedAt <= to) || (v.ResolvedAt > from && v.ResolvedAt <= to)))
            .Select(v => new { v.AssetId, v.Vulnerability!.CveId, v.Vulnerability.CvssScore, v.Vulnerability.IsKnownExploited, v.MatchStatus, v.Product, v.DetectedVersion, v.FirstDetectedAt, v.ResolvedAt })
            .ToListAsync(ct);
        var newVulns = vulns.Where(v => v.FirstDetectedAt > from && v.FirstDetectedAt <= to)
            .Select(v => new VulnerabilityChange(Ref(v.AssetId), v.CveId, v.CvssScore, v.IsKnownExploited, v.MatchStatus, v.Product, v.DetectedVersion))
            .OrderByDescending(v => v.IsKnownExploited).ThenByDescending(v => v.CvssScore).ToList();
        var resolvedVulns = vulns.Where(v => v.ResolvedAt > from && v.ResolvedAt <= to)
            .Select(v => new VulnerabilityChange(Ref(v.AssetId), v.CveId, v.CvssScore, v.IsKnownExploited, v.MatchStatus, v.Product, v.DetectedVersion))
            .OrderByDescending(v => v.CvssScore).ToList();

        var scores = await db.RiskScores.AsNoTracking().Where(r => r.ScanId == prev.Id || r.ScanId == cur.Id).Select(r => new { r.ScanId, r.AssetId, r.Score, r.Level }).ToListAsync(ct);
        var riskChanges = scores.Where(r => r.ScanId == cur.Id && r.AssetId is not null)
            .Select(r => (Now: r, Before: scores.FirstOrDefault(p => p.ScanId == prev.Id && p.AssetId == r.AssetId)))
            .Where(x => x.Before is null ? x.Now.Score >= 15 : Math.Abs(x.Now.Score - x.Before.Score) >= RiskDelta)
            .Select(x => new RiskChange(Ref(x.Now.AssetId!.Value), x.Before?.Score, x.Now.Score, x.Now.Level))
            .OrderByDescending(r => Math.Abs(r.After - (r.Before ?? 0))).ToList();

        return new ScanComparison(prev, cur, prev.Network == cur.Network, newDevices, returned, missing,
            changed.OrderByDescending(c => c.Changes.Count).ToList(), newVulns, resolvedVulns, riskChanges,
            scores.FirstOrDefault(r => r.ScanId == prev.Id && r.AssetId == null)?.Score,
            scores.FirstOrDefault(r => r.ScanId == cur.Id && r.AssetId == null)?.Score);
    }

    /// <summary>Change counts for consecutive scans of each network (newest first).</summary>
    public async Task<IReadOnlyList<TimelineEntry>> TimelineAsync(int take = 15, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var scans = await db.Scans.AsNoTracking().Where(s => s.Status == ScanStatus.Completed && s.StartedAt != null)
            .OrderByDescending(s => s.StartedAt).Select(s => new { s.Id, s.NetworkFingerprint }).Take(take).ToListAsync(ct);
        var entries = new List<TimelineEntry>();
        foreach (var s in scans)
        {
            var previous = await PreviousOnSameNetworkAsync(s.Id, ct);
            if (previous is { } p && await CompareAsync(p, s.Id, ct) is { } c)
            {
                entries.Add(new TimelineEntry(c.Current, p, c.NewDevices.Count, c.MissingDevices.Count, c.Count(AssetChangeKind.PortOpened), c.Count(AssetChangeKind.PortClosed),
                    c.Count(AssetChangeKind.VersionChanged) + c.Count(AssetChangeKind.ServiceChanged), c.NewVulnerabilities.Count, c.ResolvedVulnerabilities.Count, c.PostureAfter, c.PostureBefore));
            }
            else if ((await Project(Completed(db).Where(r => r.Id == s.Id)).ToListAsync(ct)).FirstOrDefault() is { } first)
            {
                var posture = await db.RiskScores.Where(r => r.ScanId == s.Id && r.AssetId == null).Select(r => (double?)r.Score).FirstOrDefaultAsync(ct);
                var devices = await db.DiscoveredHosts.Where(h => h.ScanId == s.Id && h.AssetId != null).Select(h => h.AssetId).Distinct().CountAsync(ct);
                entries.Add(new TimelineEntry(first, null, devices, 0, 0, 0, 0, 0, 0, posture, null));
            }
        }

        return entries;
    }

    /// <summary>One device can answer on several addresses in a scan (cable and Wi‑Fi) – compare the union of its ports.</summary>
    private static DiscoveredHost Merge(IEnumerable<DiscoveredHost> observations)
    {
        var list = observations.OrderBy(h => h.IpAddress, StringComparer.Ordinal).ToList();
        var first = list[0];
        return new DiscoveredHost
        {
            ScanId = first.ScanId, AssetId = first.AssetId, IpAddress = first.IpAddress, Hostname = first.Hostname, MacAddress = first.MacAddress,
            AssetTypeGuess = first.AssetTypeGuess, DiscoveredAt = first.DiscoveredAt,
            Ports = list.SelectMany(h => h.Ports).GroupBy(p => (p.Port, p.Protocol)).Select(g => g.First()).ToList()
        };
    }

    private static IQueryable<Scan> Completed(WelesDbContext db) =>
        db.Scans.AsNoTracking().Where(s => s.Status == ScanStatus.Completed && s.StartedAt != null);

    /// <summary>Projection last – EF cannot filter or sort on a record built by a constructor.</summary>
    private static IQueryable<ScanRef> Project(IQueryable<Scan> scans) =>
        scans.Select(s => new ScanRef(s.Id, s.StartedAt!.Value, s.ScanTarget!.Name, s.PortSpecification, s.NetworkFingerprint));
}
