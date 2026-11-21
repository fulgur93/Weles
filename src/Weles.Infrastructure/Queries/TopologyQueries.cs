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
    int KnownExploited,
    Weles.Core.Topology.LinkEvidence? Link = null);

/// <summary>
/// One network with its devices. Each device's link carries its evidence (<see cref="Weles.Core.Topology.LinkEvidence"/>):
/// observed – MAC in the ARP table (same layer-2 segment), the ICMP reply's TTL (routers in between) or a traceroute path –
/// or only inferred from the address and the gateway. No traffic is captured; the observations come from the scan's own probes.
/// </summary>
/// <param name="IsPublic">Public (Internet) hosts outside any local network – drawn without a gateway and without "same LAN" links.</param>
/// <param name="Routers">Routers seen by traceroute on the way to this network's devices (address → how many devices behind it).</param>
public sealed record TopologyNetwork(string Key, string Label, string? Cidr, TopologyNode? Gateway, IReadOnlyList<TopologyNode> Devices, bool IsPublic = false,
    IReadOnlyDictionary<string, int>? Routers = null)
{
    public int ObservedLinks => Devices.Count(d => d.Link?.Observed == true);
    public int InferredLinks => Devices.Count - ObservedLinks;
}

public sealed record TopologyModel(IReadOnlyList<TopologyNetwork> Networks, int HiddenOtherNetworks, string? CurrentNetwork);

public sealed class TopologyQueries(IDbContextFactory<WelesDbContext> contextFactory, AssetQueries assets, RiskQueries risk)
{
    /// <param name="includeAsset">Shows only devices of one network (null – as chosen by <paramref name="currentNetworkOnly"/>).</param>
    public async Task<TopologyModel> GetAsync(bool currentNetworkOnly, Func<int, bool>? includeAsset = null, CancellationToken ct = default)
    {
        var current = await assets.CurrentNetworkAsync(ct);
        var all = await assets.LoadAllAsync(ct);
        // Hosts with a public address and no local segment (Attack Surface scans) are not part of any local network.
        static bool IsPublicHost(AssetListItem a) => a.SegmentId is null && IPAddress.TryParse(a.IpAddress, out var ip) && AddressClassifier.IsPublic(ip);
        bool Hidden(AssetListItem a) => (a.SegmentId is { } s && current.OtherNetworkSegmentIds.Contains(s)) || IsPublicHost(a);
        var hidden = currentNetworkOnly ? all.Count(Hidden) : 0;
        var items = (currentNetworkOnly ? all.Where(a => !Hidden(a)) : all).Where(a => includeAsset?.Invoke(a.Id) != false).ToList();

        var results = await risk.LatestResultsAsync(ct);
        var gateways = await GatewayAssetsAsync(ct);
        var facts = await LinkFactsAsync(ct);
        TopologyNode Node(AssetListItem a)
        {
            var r = results.TryGetValue(a.Id, out var x) ? x.Result : null;
            var exposure = r?.Issues.Where(i => i.Score >= AttackPathEngine.MinimumIssueScore || i.KnownExploited > 0).Select(i => i.Title).Take(4).ToList() ?? [];
            return new TopologyNode(a.Id, a.DisplayName, a.IpAddress, a.Hostname, a.Type, gateways.Contains(a.Id), a.Status, a.RiskScore, a.RiskLevel,
                a.OpenPorts, a.Products, exposure, r?.Issues.Sum(i => i.KnownExploited) ?? 0,
                facts.TryGetValue(a.Id, out var f) ? Weles.Core.Topology.TopologyEvidence.For(f) : null);
        }

        var networks = items.GroupBy(a => IsPublicHost(a) ? "public" : a.SegmentId?.ToString() ?? "none")
            .Select(g =>
            {
                var nodes = g.Select(Node).ToList();
                if (g.Key == "public")
                {
                    return new TopologyNetwork("public", "Internet – zasoby publiczne (poza siecią lokalną)", null, null,
                        nodes.OrderByDescending(n => n.RiskScore ?? 0).ThenBy(n => n.Name, StringComparer.Ordinal).ToList(), IsPublic: true);
                }

                var gateway = nodes.Where(n => n.IsGateway).OrderBy(n => n.Ip, StringComparer.Ordinal).FirstOrDefault();
                var label = g.First().NetworkLabel ?? (g.Key == "none" ? "bez rozpoznanej sieci (np. 127.0.0.1, VPN)" : "sieć");
                var devices = nodes.Where(n => n != gateway).OrderByDescending(n => n.RiskScore ?? 0).ThenBy(n => n.Name, StringComparer.Ordinal).ToList();
                var routers = devices.SelectMany(d => d.Link?.Path ?? []).GroupBy(p => p).ToDictionary(x => x.Key, x => x.Count());
                return new TopologyNetwork(g.Key, label, g.First().SegmentCidr, gateway, devices, Routers: routers);
            })
            .OrderBy(n => n.Key is "none" or "public").ThenBy(n => n.IsPublic).ThenByDescending(n => n.Devices.Count).ToList();
        return new TopologyModel(networks, hidden, currentNetworkOnly ? current.Description : null);
    }

    /// <summary>Potential exposure paths over the latest assessment of every device.</summary>
    /// <param name="includeAsset">Limits the paths to devices of one network (null – all networks).</param>
    public async Task<IReadOnlyList<AttackPath>> AttackPathsAsync(Func<int, bool>? includeAsset = null, int take = 12, CancellationToken ct = default)
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
            if (!all.TryGetValue(assetId, out var a) || includeAsset?.Invoke(assetId) == false) continue;
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
            var overInternet = isPublic && a.SegmentId is null;
            input.Add(new PathAsset(assetId, a.DisplayName, a.IpAddress, a.Type, a.Criticality, gateways.Contains(assetId), isPublic, scanId,
                overInternet ? "Internet" : a.NetworkLabel ?? "bez rozpoznanej sieci", perNetwork.GetValueOrDefault(a.SegmentId ?? -1), issues, overInternet));
        }

        return AttackPathEngine.Build(input, take);
    }

    /// <summary>Facts of each asset's latest observation that show how it is connected (ARP, TTL, traceroute).</summary>
    private async Task<Dictionary<int, Weles.Core.Topology.LinkFacts>> LinkFactsAsync(CancellationToken ct)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var rows = await db.DiscoveredHosts.AsNoTracking().Where(h => h.AssetId != null)
            .Select(h => new { Id = h.AssetId!.Value, Row = h.Id, h.IpAddress, h.DiscoveryMethods, h.MacAddress, h.Ttl, h.TracePath })
            .ToListAsync(ct);
        return rows.GroupBy(r => r.Id).Select(g => g.MaxBy(r => r.Row)!).ToDictionary(r => r.Id, r => new Weles.Core.Topology.LinkFacts(
            r.IpAddress, r.DiscoveryMethods.HasFlag(DiscoveryMethod.Arp), r.MacAddress, r.Ttl,
            r.TracePath?.Split(',', StringSplitOptions.RemoveEmptyEntries)));
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
