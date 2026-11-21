using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Discovery;

namespace Weles.Infrastructure.Queries;

public sealed record AssetListItem(
    int Id,
    string DisplayName,
    bool HasCustomName,
    string? Hostname,
    string? IpAddress,
    string? MacAddress,
    string? Vendor,
    AssetType Type,
    bool TypeSetByUser,
    string? OsFamily,
    AssetCriticality Criticality,
    int? SegmentId,
    string? SegmentCidr,
    string? NetworkLabel,
    int OpenPortCount,
    IReadOnlyList<int> OpenPorts,
    IReadOnlyList<string> Products,
    int OpenVulnerabilities,
    double? RiskScore,
    RiskLevel? RiskLevel,
    AssetStatus Status,
    DateTime FirstSeenAt,
    DateTime LastSeenAt,
    int ObservationCount,
    PresenceSummary? Presence = null);

public enum AssetSortColumn
{
    Name, Ip, Type, Os, Vendor, OpenPorts, Vulnerabilities, Risk, Criticality, Status, FirstSeen, LastSeen
}

public sealed record AssetSort(AssetSortColumn Column, bool Descending);

public sealed record AssetListQuery
{
    public string? Search { get; init; }
    public IReadOnlySet<AssetType> Types { get; init; } = new HashSet<AssetType>();
    public IReadOnlySet<AssetStatus> Statuses { get; init; } = new HashSet<AssetStatus>();
    /// <summary>Segments (networks) to show; null = every network, including assets without a segment.</summary>
    public IReadOnlySet<int>? SegmentIds { get; init; }

    /// <summary>Segments to hide (other networks in the current-network view).</summary>
    public IReadOnlySet<int>? ExcludedSegmentIds { get; init; }
    public string? OsFamily { get; init; }
    public bool OnlyWithOpenPorts { get; init; }
    public IReadOnlyList<AssetSort> Sort { get; init; } = [new(AssetSortColumn.Ip, false)];
    public int Page { get; init; } = 1;
    public int PageSize { get; init; } = 25;
}

public sealed record AssetListPage(
    IReadOnlyList<AssetListItem> Items,
    int TotalCount,
    int Page,
    int PageSize,
    int AllStatusesCount,
    int HiddenOtherNetworks,
    IReadOnlyDictionary<AssetStatus, int> StatusCounts,
    IReadOnlyDictionary<AssetType, int> TypeCounts,
    IReadOnlyList<(int Id, string Label)> Segments,
    IReadOnlyList<string> OsFamilies)
{
    public int PageCount => Math.Max(1, (int)Math.Ceiling(TotalCount / (double)PageSize));
}

public sealed record AssetObservation(DiscoveredHost Host, int ScanId, DateTime ScanStartedAt, string ScanTargetName, IReadOnlyList<AssetChange> ChangesSincePrevious);

/// <param name="CurrentPorts">Last known open ports, each from the latest scan that checked it.</param>
public sealed record AssetDetail(
    Asset Asset,
    AssetPresence Presence,
    DiscoveredHost? Latest,
    IReadOnlyList<DiscoveredPort> CurrentPorts,
    IReadOnlyList<AssetObservation> Observations,
    IReadOnlyList<CompletedScanCoverage> Absences,
    IReadOnlyList<AssetVulnerability> Vulnerabilities,
    PresenceSummary? PresenceHistory = null);

/// <summary>
/// Read model for the asset inventory. Data is loaded once per request and filtered/sorted in memory: a local
/// inventory holds at most tens of thousands of assets, and in-memory evaluation gives culture-aware (Polish)
/// case-insensitive search and arbitrary multi-column sorting, which SQLite LIKE/ORDER BY cannot.
/// </summary>
/// <param name="OtherNetworkSegmentIds">
/// Segments that belong to a different, identified network (known gateway MAC, not the one this machine is attached
/// to now). The current-network view hides exactly these; loopback, routed or unidentified segments stay visible.
/// </param>
/// <param name="Description">Attached networks, e.g. "192.168.0.0/24 · TP-LINK c0:4a:00:ee:19:4a".</param>
public sealed record CurrentNetworkView(IReadOnlySet<int> OtherNetworkSegmentIds, string Description);

public sealed class AssetQueries(IDbContextFactory<WelesDbContext> contextFactory, ICurrentNetworkProvider? currentNetwork = null)
{
    public async Task<CurrentNetworkView> CurrentNetworkAsync(CancellationToken ct = default)
    {
        var attached = currentNetwork?.GetAttachedNetworks() ?? [];
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var segments = await db.NetworkSegments.AsNoTracking().Select(s => new { s.Id, s.Cidr, s.Name, s.GatewayMac, s.GatewayVendor }).ToListAsync(ct);
        // The same router and overlapping addresses: a scope narrower than the interface network (a /24 scanned inside
        // a /20) is still this network – an exact CIDR match hid every device of such a scope as "another network".
        bool IsAttached(string cidr, string? mac) => attached.Any(n => NetworkIdentity.CidrsOverlap(n.Cidr, cidr) && NetworkIdentity.SameNetwork(n.GatewayMac, mac));

        var others = attached.Count == 0
            ? new HashSet<int>()
            : segments.Where(s => s.GatewayMac is not null && !IsAttached(s.Cidr, s.GatewayMac)).Select(s => s.Id).ToHashSet();
        var description = string.Join(", ", attached.Select(n =>
            segments.Where(s => s.GatewayMac is not null && NetworkIdentity.CidrsOverlap(s.Cidr, n.Cidr) && NetworkIdentity.SameNetwork(n.GatewayMac, s.GatewayMac))
                .OrderByDescending(s => s.Cidr == n.Cidr).FirstOrDefault() is { } seg
                ? NetworkNaming.Label(seg.Cidr, seg.Name, seg.GatewayVendor, seg.GatewayMac)
                : NetworkNaming.Label(n.Cidr, null, null, n.GatewayMac)));
        return new CurrentNetworkView(others, description);
    }

    private const int CoverageScanLimit = 200;

    public async Task<IReadOnlyList<AssetListItem>> LoadAllAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);

        var assets = await db.Assets.AsNoTracking()
            .Select(a => new
            {
                a.Id, a.DisplayName, a.CustomName, a.Hostname, a.PrimaryIpAddress, a.MacAddress, a.Vendor, a.AssetType, a.UserAssetType,
                a.OsFamily, a.Criticality, a.NetworkSegmentId, Cidr = a.NetworkSegment != null ? a.NetworkSegment.Cidr : null,
                SegmentName = a.NetworkSegment != null ? a.NetworkSegment.Name : null,
                GatewayVendor = a.NetworkSegment != null ? a.NetworkSegment.GatewayVendor : null,
                GatewayMac = a.NetworkSegment != null ? a.NetworkSegment.GatewayMac : null,
                a.CurrentRiskScore, a.CurrentRiskLevel, a.FirstSeenAt, a.LastSeenAt,
                OpenVulns = a.Vulnerabilities.Count(v => v.Status == FindingStatus.Open && v.MatchStatus != VulnerabilityMatchStatus.InsufficientData)
            })
            .ToListAsync(ct);

        var observations = await db.DiscoveredHosts.AsNoTracking()
            .Where(h => h.AssetId != null && h.Scan!.Status != ScanStatus.Running && h.Scan.Status != ScanStatus.Pending)
            .Select(h => new { AssetId = h.AssetId!.Value, h.Id, h.ScanId, h.DiscoveredAt, h.Scan!.PortSpecification, h.Scan.NetworkFingerprint })
            .ToListAsync(ct);

        var byAsset = observations.GroupBy(o => o.AssetId).ToDictionary(g => g.Key, g => g.OrderBy(o => o.DiscoveredAt).ToList());
        var checkedByScan = observations.Select(o => (o.ScanId, o.PortSpecification)).Distinct().ToDictionary(o => o.ScanId, o => CheckedPorts(o.PortSpecification));

        var openPorts = await db.DiscoveredPorts.AsNoTracking()
            .Where(p => p.Host!.AssetId != null && p.State == PortState.Open && p.Protocol == TransportProtocol.Tcp)
            .Select(p => new CurrentPort(p.DiscoveredHostId, p.Port, p.Service != null ? p.Service.Product : null, p.Service != null ? p.Service.Version : null))
            .ToListAsync(ct);
        var portsByHost = openPorts.GroupBy(p => p.HostId).ToDictionary(g => g.Key, g => (IReadOnlyList<CurrentPort>)g.ToList());

        var coverage = await LoadCoverageAsync(db, ct);

        return assets.Select(a =>
        {
            var obs = byAsset.GetValueOrDefault(a.Id) ?? [];
            var ports = MergeCurrentPorts(obs.Select(o => (portsByHost.GetValueOrDefault(o.Id) ?? [], checkedByScan[o.ScanId])));
            var presence = AssetStatusRules.Evaluate(a.PrimaryIpAddress, coverage, obs.Select(o => o.ScanId).ToHashSet(), obs.FirstOrDefault()?.ScanId,
                obs.Count > 0 ? obs[^1].NetworkFingerprint : null);
            return new AssetListItem(
                a.Id, a.DisplayName, a.CustomName is not null, a.Hostname, a.PrimaryIpAddress, a.MacAddress, a.Vendor,
                a.UserAssetType ?? a.AssetType, a.UserAssetType is not null, a.OsFamily, a.Criticality, a.NetworkSegmentId, a.Cidr,
                a.Cidr is null ? null : NetworkNaming.Label(a.Cidr, a.SegmentName, a.GatewayVendor, a.GatewayMac),
                ports.Count, ports.Select(p => p.Port).Order().ToList(),
                ports.Where(p => p.Product is not null).Select(p => p.Version is null ? p.Product! : $"{p.Product} {p.Version}").Distinct().ToList(),
                a.OpenVulns, a.CurrentRiskScore, a.CurrentRiskLevel, presence.Status, a.FirstSeenAt, a.LastSeenAt, obs.Count,
                Presence(a.PrimaryIpAddress, coverage, obs.Select(o => o.ScanId).ToHashSet(), obs.Count > 0 ? obs[^1].NetworkFingerprint : null));
        }).ToList();
    }

    private sealed record CurrentPort(int HostId, int Port, string? Product, string? Version);

    /// <summary>Same rule as <see cref="ObservationComparer.Replay"/>: each port keeps the state from the latest scan that checked it.</summary>
    private static List<CurrentPort> MergeCurrentPorts(IEnumerable<(IReadOnlyList<CurrentPort> Open, IReadOnlySet<int>? Checked)> chronological)
    {
        var known = new Dictionary<int, CurrentPort>();
        foreach (var (open, checkedPorts) in chronological)
        {
            foreach (var port in known.Keys.Where(p => checkedPorts is null || checkedPorts.Contains(p)).ToList()) known.Remove(port);
            foreach (var port in open) known[port.Port] = port;
        }

        return known.Values.OrderBy(p => p.Port).ToList();
    }

    public async Task<AssetListPage> QueryAsync(AssetListQuery query, CancellationToken ct = default) =>
        AssetListEngine.Apply(await LoadAllAsync(ct), query);

    public async Task<AssetDetail?> GetAsync(int assetId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var asset = await db.Assets.AsNoTracking().Include(a => a.NetworkSegment).SingleOrDefaultAsync(a => a.Id == assetId, ct);
        if (asset is null) return null;

        var hosts = await db.DiscoveredHosts.AsNoTracking().AsSplitQuery()
            .Where(h => h.AssetId == assetId && h.Scan!.Status != ScanStatus.Running && h.Scan.Status != ScanStatus.Pending)
            .Include(h => h.Scan!).ThenInclude(s => s.ScanTarget)
            .Include(h => h.Ports).ThenInclude(p => p.Service).ThenInclude(s => s!.Certificates)
            .OrderBy(h => h.DiscoveredAt)
            .ToListAsync(ct);

        var history = ObservationComparer.Replay(hosts.Select(h => new PortObservation(h, CheckedPorts(h.Scan!.PortSpecification))).ToList());
        var observations = new List<AssetObservation>();
        for (var i = 0; i < hosts.Count; i++)
        {
            var h = hosts[i];
            observations.Add(new AssetObservation(h, h.ScanId, h.Scan!.StartedAt ?? h.Scan.CreatedAt, h.Scan.ScanTarget!.Name, history.Changes[i]));
        }

        observations.Reverse();

        var coverage = await LoadCoverageAsync(db, ct);
        var observed = hosts.Select(h => h.ScanId).ToHashSet();
        var network = hosts.LastOrDefault()?.Scan!.NetworkFingerprint;
        var presence = AssetStatusRules.Evaluate(asset.PrimaryIpAddress, coverage, observed, hosts.FirstOrDefault()?.ScanId, network);
        var firstObservedAt = hosts.Count > 0 ? hosts[0].Scan!.StartedAt ?? hosts[0].Scan!.CreatedAt : asset.FirstSeenAt;
        var absences = AssetStatusRules.Absences(asset.PrimaryIpAddress, coverage, observed, firstObservedAt, network).Take(20).ToList();

        var vulnerabilities = await db.AssetVulnerabilities.AsNoTracking()
            .Where(v => v.AssetId == assetId)
            .Include(v => v.Vulnerability)
            .OrderBy(v => v.Status).ThenByDescending(v => v.Vulnerability!.CvssScore)
            .ToListAsync(ct);

        return new AssetDetail(asset, presence, hosts.LastOrDefault(), history.CurrentPorts, observations, absences, vulnerabilities,
            Presence(asset.PrimaryIpAddress, coverage, observed, network));
    }

    /// <summary>Behaviour across the covering scans (newest first): stability, misses in a row, time-of-day pattern.</summary>
    internal static PresenceSummary Presence(string? ip, IReadOnlyList<CompletedScanCoverage> coverage, IReadOnlySet<int> observed, string? network) =>
        PresenceHistory.Analyze(coverage.Where(s => observed.Contains(s.ScanId) || s.Covers(ip, network))
            .Select(s => (s.StartedAt.ToLocalTime(), observed.Contains(s.ScanId))).ToList());

    /// <summary>Ports a scan checked; null when its specification can no longer be parsed (then every port counts as checked).</summary>
    internal static IReadOnlySet<int>? CheckedPorts(string specification) =>
        PortSpecification.TryParse(specification, out var ports, out _) ? ports.ToHashSet() : null;

    private static async Task<List<CompletedScanCoverage>> LoadCoverageAsync(WelesDbContext db, CancellationToken ct)
    {
        var scans = await db.Scans.AsNoTracking()
            .Where(s => s.Status == ScanStatus.Completed && s.StartedAt != null)
            .OrderByDescending(s => s.StartedAt)
            .Take(CoverageScanLimit)
            .Select(s => new { s.Id, StartedAt = s.StartedAt!.Value, s.ScopeSnapshot, s.NetworkFingerprint })
            .ToListAsync(ct);
        return scans.Select(s => new CompletedScanCoverage(s.Id, s.StartedAt, ScopeCoverage.FromSnapshot(s.ScopeSnapshot), s.NetworkFingerprint)).ToList();
    }
}

/// <summary>Search, filters, multi-column sort and paging over the loaded inventory.</summary>
public static class AssetListEngine
{
    private static readonly StringComparer PolishComparer = StringComparer.Create(CultureInfo.GetCultureInfo("pl-PL"), ignoreCase: true);

    public static AssetListPage Apply(IReadOnlyList<AssetListItem> all, AssetListQuery query)
    {
        IEnumerable<AssetListItem> filtered = all;

        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            var terms = query.Search.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(Fold).ToArray();
            filtered = filtered.Where(a => terms.All(t => Matches(a, t)));
        }

        // Facet counts reflect the search but not the facet's own filter, so the user sees what each choice would give.
        var searched = filtered.ToList();
        if (query.SegmentIds is { } segmentIds) searched = searched.Where(a => a.SegmentId is { } id && segmentIds.Contains(id)).ToList();
        var hiddenByNetwork = 0;
        if (query.ExcludedSegmentIds is { Count: > 0 } excluded)
        {
            var before = searched.Count;
            searched = searched.Where(a => a.SegmentId is not { } id || !excluded.Contains(id)).ToList();
            hiddenByNetwork = before - searched.Count;
        }
        if (!string.IsNullOrEmpty(query.OsFamily)) searched = searched.Where(a => string.Equals(a.OsFamily, query.OsFamily, StringComparison.OrdinalIgnoreCase)).ToList();
        if (query.OnlyWithOpenPorts) searched = searched.Where(a => a.OpenPortCount > 0).ToList();

        var byType = searched.Where(a => query.Types.Count == 0 || query.Types.Contains(a.Type)).ToList();
        var statusCounts = Enum.GetValues<AssetStatus>().ToDictionary(st => st, st => byType.Count(a => HasStatus(a, st)));
        var typeCounts = searched.Where(a => MatchesStatuses(a, query.Statuses)).GroupBy(a => a.Type).ToDictionary(g => g.Key, g => g.Count());

        var result = byType.Where(a => MatchesStatuses(a, query.Statuses)).ToList();

        var sorted = Sort(result, query.Sort);
        var pageSize = Math.Clamp(query.PageSize, 1, 500);
        var pageCount = Math.Max(1, (int)Math.Ceiling(result.Count / (double)pageSize));
        var page = Math.Clamp(query.Page, 1, pageCount);

        return new AssetListPage(
            sorted.Skip((page - 1) * pageSize).Take(pageSize).ToList(),
            result.Count, page, pageSize, byType.Count, hiddenByNetwork, statusCounts, typeCounts,
            all.Where(a => a.SegmentId is not null).Select(a => (a.SegmentId!.Value, a.NetworkLabel ?? a.SegmentCidr!)).Distinct().OrderBy(s => s.Item2).ToList(),
            all.Select(a => a.OsFamily).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).Order().ToList());
    }

    /// <summary>
    /// "Active" means present in the latest scan that covered the device – a device found for the first time is active
    /// too ("New" is the narrower view). Found on a real network: after a first scan the "Active" tab was empty.
    /// </summary>
    public static bool HasStatus(AssetListItem a, AssetStatus status) =>
        a.Status == status || (status == AssetStatus.Active && a.Status == AssetStatus.New);

    private static bool MatchesStatuses(AssetListItem a, IReadOnlySet<AssetStatus> statuses) =>
        statuses.Count == 0 || statuses.Any(st => HasStatus(a, st));

    private static bool Matches(AssetListItem a, string term)
    {
        if (int.TryParse(term, out var port) && a.OpenPorts.Contains(port)) return true; // term is already folded; digits are unchanged
        return Contains(a.DisplayName, term) || Contains(a.Hostname, term) || Contains(a.IpAddress, term) || Contains(a.MacAddress, term)
               || Contains(a.Vendor, term) || Contains(a.OsFamily, term) || Contains(a.NetworkLabel, term) || a.Products.Any(p => Contains(p, term));
    }

    private static bool Contains(string? value, string foldedTerm) =>
        value is not null && Fold(value).Contains(foldedTerm, StringComparison.Ordinal);

    /// <summary>
    /// Lower-case, diacritics removed. "ł" is a separate letter in Unicode (no combining mark), so it is mapped explicitly:
    /// "Łódź" → "lodz".
    /// </summary>
    public static string Fold(string value)
    {
        var decomposed = value.ToLowerInvariant().Replace('ł', 'l').Normalize(System.Text.NormalizationForm.FormD);
        var sb = new System.Text.StringBuilder(decomposed.Length);
        foreach (var c in decomposed)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark) sb.Append(c);
        }

        return sb.ToString();
    }

    private static IEnumerable<AssetListItem> Sort(List<AssetListItem> items, IReadOnlyList<AssetSort> sort)
    {
        var keys = sort.Count == 0 ? [new AssetSort(AssetSortColumn.Ip, false)] : sort;
        IOrderedEnumerable<AssetListItem>? ordered = null;
        foreach (var key in keys)
        {
            ordered = key.Column switch
            {
                AssetSortColumn.Name => Then(ordered, items, a => a.DisplayName, key.Descending, PolishComparer),
                AssetSortColumn.Ip => Then(ordered, items, a => IpKey(a.IpAddress), key.Descending, StringComparer.Ordinal),
                AssetSortColumn.Type => Then(ordered, items, a => a.Type, key.Descending),
                AssetSortColumn.Os => Then(ordered, items, a => a.OsFamily ?? "￿", key.Descending, PolishComparer),
                AssetSortColumn.Vendor => Then(ordered, items, a => a.Vendor ?? "￿", key.Descending, PolishComparer),
                AssetSortColumn.OpenPorts => Then(ordered, items, a => a.OpenPortCount, key.Descending),
                AssetSortColumn.Vulnerabilities => Then(ordered, items, a => a.OpenVulnerabilities, key.Descending),
                AssetSortColumn.Risk => Then(ordered, items, a => a.RiskScore ?? -1, key.Descending),
                AssetSortColumn.Criticality => Then(ordered, items, a => a.Criticality, key.Descending),
                AssetSortColumn.Status => Then(ordered, items, a => a.Status, key.Descending),
                AssetSortColumn.FirstSeen => Then(ordered, items, a => a.FirstSeenAt, key.Descending),
                AssetSortColumn.LastSeen => Then(ordered, items, a => a.LastSeenAt, key.Descending),
                _ => ordered ?? items.OrderBy(a => a.Id)
            };
        }

        return ordered!.ThenBy(a => a.Id);
    }

    private static IOrderedEnumerable<AssetListItem> Then<TKey>(IOrderedEnumerable<AssetListItem>? ordered, List<AssetListItem> items, Func<AssetListItem, TKey> key, bool descending, IComparer<TKey>? comparer = null) =>
        ordered is null
            ? descending ? items.OrderByDescending(key, comparer) : items.OrderBy(key, comparer)
            : descending ? ordered.ThenByDescending(key, comparer) : ordered.ThenBy(key, comparer);

    /// <summary>Numeric IP ordering (10.0.0.2 before 10.0.0.10).</summary>
    public static string IpKey(string? ip) =>
        System.Net.IPAddress.TryParse(ip, out var a) ? Convert.ToHexString(a.GetAddressBytes()).PadLeft(32, '0') : "￿" + ip;
}
