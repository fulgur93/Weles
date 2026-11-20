using System.Net;
using Microsoft.EntityFrameworkCore;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Database;

namespace Weles.Infrastructure.Queries;

/// <summary>A network the user can pick: a router (gateway MAC), a segment without a gateway (VPN, routed), or public hosts.</summary>
public sealed record NetworkOption(string Key, string Label, int Devices, bool IsCurrent);

/// <summary>
/// Which network every device and every scan belongs to, and which networks this computer is attached to now.
/// Pages use it to show one network at a time instead of mixing the home LAN, other Wi‑Fi networks, VPNs and the Internet.
/// </summary>
/// <param name="AssetNetwork">Asset id → network key.</param>
/// <param name="ScanNetwork">Completed scan id → network key.</param>
public sealed record NetworkContext(
    IReadOnlyList<NetworkOption> Networks,
    IReadOnlyDictionary<int, string> AssetNetwork,
    IReadOnlyDictionary<int, string> ScanNetwork,
    string CurrentDescription)
{
    public const string All = "all";
    public const string Current = "current";
    /// <summary>All public hosts together; each external scope (domain) also has its own key "ext:{scope id}".</summary>
    public const string Public = "public";
    public const string ExternalPrefix = "ext:";

    public static bool IsPublicKey(string key) => key == Public || key.StartsWith(ExternalPrefix, StringComparison.Ordinal);
    public const string Unidentified = "none";

    public IReadOnlySet<string> CurrentKeys { get; } = Networks.Where(n => n.IsCurrent).Select(n => n.Key).ToHashSet();

    /// <summary>"Current network" is offered only when it hides something.</summary>
    public bool OffersCurrent => CurrentKeys.Count > 0 && Networks.Any(n => !n.IsCurrent);

    public string DefaultFilter => OffersCurrent ? Current : All;

    /// <summary>"Internet – all public hosts" is offered when public hosts come from more than one scope.</summary>
    public bool OffersPublicGroup => Networks.Count(n => IsPublicKey(n.Key)) > 1;

    /// <summary>A valid filter value: "all", "current", "public" or a known network key; anything else falls back to the default.</summary>
    public string Normalize(string? filter) =>
        filter == All || (filter == Current && OffersCurrent) || (filter == Public && Networks.Any(n => IsPublicKey(n.Key))) || Networks.Any(n => n.Key == filter)
            ? filter! : DefaultFilter;

    public bool Includes(string filter, string key) => filter switch
    {
        All => true,
        Current => CurrentKeys.Contains(key),
        Public => IsPublicKey(key),
        _ => key == filter
    };

    public bool IncludesAsset(string filter, int assetId) => Includes(filter, AssetNetwork.GetValueOrDefault(assetId, Unidentified));

    public bool IncludesScan(string filter, int scanId) => Includes(filter, ScanNetwork.GetValueOrDefault(scanId, Unidentified));

    public string LabelOf(string key) => key == Public ? "Internet – wszystkie zasoby publiczne" : Networks.FirstOrDefault(n => n.Key == key)?.Label ?? key;

    public string AssetNetworkKey(int assetId) => AssetNetwork.GetValueOrDefault(assetId, Unidentified);

    public string ScanNetworkKey(int scanId) => ScanNetwork.GetValueOrDefault(scanId, Unidentified);
}

public sealed class NetworkQueries(IDbContextFactory<WelesDbContext> contextFactory, AssetQueries assets)
{
    public async Task<NetworkContext> ContextAsync(CancellationToken ct = default)
    {
        var current = await assets.CurrentNetworkAsync(ct);
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var segments = await db.NetworkSegments.AsNoTracking().Select(s => new { s.Id, s.Cidr, s.Name, s.GatewayMac, s.GatewayVendor }).ToListAsync(ct);
        var segmentById = segments.ToDictionary(s => s.Id);
        var assetRows = await db.Assets.AsNoTracking().Select(a => new { a.Id, a.NetworkSegmentId, a.PrimaryIpAddress }).ToListAsync(ct);

        string KeyOfSegment(int id) => segmentById.TryGetValue(id, out var s) && s.GatewayMac is { } mac ? GatewayKey(mac) : $"seg:{id}";
        string KeyOfAsset(int? segmentId, string? ip) => segmentId is { } id ? KeyOfSegment(id)
            : IPAddress.TryParse(ip, out var address) && AddressClassifier.IsPublic(address) ? NetworkContext.Public
            : NetworkContext.Unidentified;

        // A public host belongs to the external scope (domain) that last observed it – two domains are not one network.
        var scans = await db.Scans.AsNoTracking().Where(s => s.Status == ScanStatus.Completed)
            .Select(s => new { s.Id, s.NetworkFingerprint, s.ScanTarget!.IsExternal, s.ScanTargetId, ScopeName = s.ScanTarget.Name }).ToListAsync(ct);
        var externalScans = scans.Where(s => s.IsExternal).ToDictionary(s => s.Id);
        var externalIds = externalScans.Keys.ToList();
        var publicScope = (await db.DiscoveredHosts.AsNoTracking().Where(h => externalIds.Contains(h.ScanId) && h.AssetId != null)
                .Select(h => new { AssetId = h.AssetId!.Value, h.ScanId }).ToListAsync(ct))
            .GroupBy(h => h.AssetId).ToDictionary(g => g.Key, g => externalScans[g.Max(h => h.ScanId)].ScanTargetId);

        var assetNetwork = assetRows.ToDictionary(a => a.Id, a =>
        {
            var key = KeyOfAsset(a.NetworkSegmentId, a.PrimaryIpAddress);
            return key == NetworkContext.Public && publicScope.TryGetValue(a.Id, out var scope) ? NetworkContext.ExternalPrefix + scope : key;
        });

        // A scan belongs to its gateway's network; without a gateway (VPN, loopback) to the network most of its devices are in.
        var withoutGateway = scans.Where(s => s.NetworkFingerprint is null && !s.IsExternal).Select(s => s.Id).ToList();
        var hostAssets = await db.DiscoveredHosts.AsNoTracking().Where(h => withoutGateway.Contains(h.ScanId) && h.AssetId != null)
            .Select(h => new { h.ScanId, AssetId = h.AssetId!.Value }).ToListAsync(ct);
        var majority = hostAssets.GroupBy(h => h.ScanId).ToDictionary(g => g.Key,
            g => g.GroupBy(h => assetNetwork.GetValueOrDefault(h.AssetId, NetworkContext.Unidentified)).OrderByDescending(x => x.Count()).ThenBy(x => x.Key, StringComparer.Ordinal).First().Key);
        var scanNetwork = scans.ToDictionary(s => s.Id, s =>
            s.IsExternal ? NetworkContext.ExternalPrefix + s.ScanTargetId
            : s.NetworkFingerprint is { } fp ? GatewayKey(fp)
            : majority.GetValueOrDefault(s.Id, NetworkContext.Unidentified));

        // Labels: the segment name for a router network (the most populated segment when one router served several).
        var labels = new Dictionary<string, string>
        {
            [NetworkContext.Public] = "Internet – zasoby publiczne (spoza zakresów zewnętrznych)",
            [NetworkContext.Unidentified] = "bez rozpoznanej sieci (np. 127.0.0.1)"
        };
        foreach (var group in segments.GroupBy(s => KeyOfSegment(s.Id)))
        {
            var main = group.OrderByDescending(s => assetRows.Count(a => a.NetworkSegmentId == s.Id)).First();
            labels[group.Key] = NetworkNaming.Label(main.Cidr, main.Name, main.GatewayVendor, main.GatewayMac);
        }

        foreach (var scope in externalScans.Values.DistinctBy(s => s.ScanTargetId))
        {
            labels[NetworkContext.ExternalPrefix + scope.ScanTargetId] = $"Internet – {scope.ScopeName}";
        }

        bool IsCurrent(string key) => !NetworkContext.IsPublicKey(key)
            && !segments.Where(s => KeyOfSegment(s.Id) == key).Any(s => current.OtherNetworkSegmentIds.Contains(s.Id));

        var keys = assetNetwork.Values.Concat(scanNetwork.Values).Distinct().ToList();
        var networks = keys.Select(k => new NetworkOption(k, labels.GetValueOrDefault(k, k), assetNetwork.Values.Count(v => v == k), IsCurrent(k)))
            .OrderByDescending(n => n.IsCurrent).ThenBy(n => NetworkContext.IsPublicKey(n.Key) || n.Key == NetworkContext.Unidentified).ThenByDescending(n => n.Devices)
            .ThenBy(n => n.Label, StringComparer.Ordinal).ToList();
        return new NetworkContext(networks, assetNetwork, scanNetwork, current.Description);
    }

    /// <summary>"gw:c0:4a:00:ee:19:4a" – the first gateway MAC identifies a router network.</summary>
    public static string GatewayKey(string fingerprint) => "gw:" + fingerprint.Split(',')[0].Trim().ToLowerInvariant();
}
