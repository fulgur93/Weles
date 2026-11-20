using System.Net;
using Microsoft.EntityFrameworkCore;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Risk;
using Weles.Infrastructure.Database;

namespace Weles.Infrastructure.Queries;

/// <summary>A device on the map. <see cref="Exposure"/> lists the issues that make it a potential exposure point.</summary>
public sealed record TopologyNode(
    int AssetId,
    string Name,
    string? Ip,
    string? Hostname,
    AssetType Type,
    bool IsGateway,
    AssetStatus Status,
    double? RiskScore,
    RiskLevel? RiskLevel,
    IReadOnlyList<int> OpenPorts,
    IReadOnlyList<string> Products,
    IReadOnlyList<string> Exposure,
    int KnownExploited);

/// <summary>
/// One network with its devices. Links are inferred, not observed traffic: every device of a segment reaches the others
/// and the gateway directly (same LAN); the gateway connects the segment to other networks and the Internet.
/// </summary>
public sealed record TopologyNetwork(string Key, string Label, string? Cidr, TopologyNode? Gateway, IReadOnlyList<TopologyNode> Devices);

public sealed record TopologyModel(IReadOnlyList<TopologyNetwork> Networks, int HiddenOtherNetworks, string? CurrentNetwork);

public sealed class TopologyQueries(IDbContextFactory<WelesDbContext> contextFactory, AssetQueries assets, RiskQueries risk)
{
    public async Task<TopologyModel> GetAsync(bool currentNetworkOnly, CancellationToken ct = default)
    {
        var current = await assets.CurrentNetworkAsync(ct);
        var all = await assets.LoadAllAsync(ct);
        var hidden = currentNetworkOnly ? all.Count(a => a.SegmentId is { } s && current.OtherNetworkSegmentIds.Contains(s)) : 0;
        var items = currentNetworkOnly ? all.Where(a => a.SegmentId is not { } s || !current.OtherNetworkSegmentIds.Contains(s)).ToList() : all.ToList();

        var results = await risk.LatestResultsAsync(ct);
        var gateways = await GatewayAssetsAsync(ct);
        TopologyNode Node(AssetListItem a)
        {
            var r = results.TryGetValue(a.Id, out var x) ? x.Result : null;
            var exposure = r?.Issues.Where(i => i.Score >= AttackPathEngine.MinimumIssueScore || i.KnownExploited > 0).Select(i => i.Title).Take(4).ToList() ?? [];
            return new TopologyNode(a.Id, a.DisplayName, a.IpAddress, a.Hostname, a.Type, gateways.Contains(a.Id), a.Status, a.RiskScore, a.RiskLevel,
                a.OpenPorts, a.Products, exposure, r?.Issues.Sum(i => i.KnownExploited) ?? 0);
        }

        var networks = items.GroupBy(a => a.SegmentId)
            .Select(g =>
            {
                var nodes = g.Select(Node).ToList();
                var gateway = nodes.Where(n => n.IsGateway).OrderBy(n => n.Ip, StringComparer.Ordinal).FirstOrDefault();
                var label = g.First().NetworkLabel ?? (g.Key is null ? "bez rozpoznanej sieci (np. 127.0.0.1, VPN)" : "sieć");
                return new TopologyNetwork(g.Key?.ToString() ?? "none", label, g.First().SegmentCidr, gateway,
                    nodes.Where(n => n != gateway).OrderByDescending(n => n.RiskScore ?? 0).ThenBy(n => n.Name, StringComparer.Ordinal).ToList());
            })
            .OrderBy(n => n.Key == "none").ThenByDescending(n => n.Devices.Count).ToList();
        return new TopologyModel(networks, hidden, currentNetworkOnly ? current.Description : null);
    }

    /// <summary>Potential exposure paths over the latest assessment of every device.</summary>
    public async Task<IReadOnlyList<AttackPath>> AttackPathsAsync(CancellationToken ct = default)
    {
        var results = await risk.LatestResultsAsync(ct);
        if (results.Count == 0) return [];
        var all = (await assets.LoadAllAsync(ct)).ToDictionary(a => a.Id);
        var gateways = await GatewayAssetsAsync(ct);
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var ids = results.Keys.ToList();
        var vulns = await db.AssetVulnerabilities.AsNoTracking().Where(v => ids.Contains(v.AssetId) && v.Status == FindingStatus.Open)
            .Select(v => new { v.AssetId, v.Vulnerability!.CveId, v.MatchStatus, v.MatchConfidence }).ToListAsync(ct);
        var findings = await db.RiskFindings.AsNoTracking().Where(f => ids.Contains(f.AssetId) && f.Status == FindingStatus.Open)
            .Select(f => new { f.AssetId, f.RuleId, f.Port, f.Confidence, f.Evidence }).ToListAsync(ct);
        var perNetwork = all.Values.GroupBy(a => a.SegmentId).ToDictionary(g => g.Key ?? -1, g => g.Count());

        var input = new List<PathAsset>();
        foreach (var (assetId, (result, scanId)) in results)
        {
            if (!all.TryGetValue(assetId, out var a)) continue;
            var issues = new List<PathIssue>();
            foreach (var i in result.Issues)
            {
                if (i.CveIds is { Count: > 0 } cves)
                {
                    var match = vulns.FirstOrDefault(v => v.AssetId == assetId && v.CveId == cves[0]);
                    var (certainty, text) = match?.MatchStatus switch
                    {
                        VulnerabilityMatchStatus.Confirmed => (90, "Dopasowanie potwierdzone (dokładna wersja z banera)"),
                        VulnerabilityMatchStatus.Probable => (70, "Dopasowanie prawdopodobne"),
                        VulnerabilityMatchStatus.NeedsVerification => (45, "Dopasowanie wymaga weryfikacji (np. pakiet dystrybucji z przeniesionymi poprawkami)"),
                        _ => (20, "Za mało danych (np. nieznana wersja firmware)")
                    };
                    issues.Add(new PathIssue(i.Title, i.Score, i.Port, cves[0], certainty, text, i.KnownExploited > 0));
                }
                else
                {
                    var f = findings.FirstOrDefault(x => x.AssetId == assetId && x.RuleId == i.RuleId && x.Port == i.Port);
                    issues.Add(new PathIssue(i.Title, i.Score, i.Port, null, f?.Confidence ?? 60, $"Dowód ze skanu: {f?.Evidence ?? i.Title}", false, i.RuleId == RiskRules.Upnp.Id));
                }
            }

            var isPublic = IPAddress.TryParse(a.IpAddress, out var ip) && AddressClassifier.IsPublic(ip);
            input.Add(new PathAsset(assetId, a.DisplayName, a.IpAddress, a.Type, a.Criticality, gateways.Contains(assetId), isPublic, scanId,
                a.NetworkLabel ?? "bez rozpoznanej sieci", perNetwork.GetValueOrDefault(a.SegmentId ?? -1), issues));
        }

        return AttackPathEngine.Build(input);
    }

    /// <summary>Assets whose latest observation was the default gateway of its segment.</summary>
    private async Task<HashSet<int>> GatewayAssetsAsync(CancellationToken ct)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        // Small table per device – evaluated in memory, a grouped "latest row" does not translate to SQLite reliably.
        var rows = await db.DiscoveredHosts.AsNoTracking().Where(h => h.AssetId != null).Select(h => new { Id = h.AssetId!.Value, Row = h.Id, h.IsGateway }).ToListAsync(ct);
        var latest = rows.GroupBy(r => r.Id).Select(g => g.MaxBy(r => r.Row)!).ToList();
        return latest.Where(x => x.IsGateway).Select(x => x.Id).ToHashSet();
    }
}
