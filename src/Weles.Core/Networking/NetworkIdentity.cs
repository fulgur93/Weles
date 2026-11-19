namespace Weles.Core.Networking;

/// <summary>
/// Identifies the physical network a scan ran on by the MAC address(es) of its gateway. Private address ranges are
/// reused everywhere: 192.168.0.0/24 at home and 192.168.0.0/24 in the office are different networks, and a scan of
/// one must not say anything about devices of the other.
/// </summary>
public static class NetworkIdentity
{
    /// <summary>Normalised fingerprint ("aa:bb:..,cc:dd:..") or null when no gateway MAC is known.</summary>
    public static string? Fingerprint(IEnumerable<string?> gatewayMacs)
    {
        var macs = gatewayMacs.Where(m => !string.IsNullOrWhiteSpace(m)).Select(m => m!.Trim().ToLowerInvariant()).Distinct().Order().ToList();
        return macs.Count == 0 ? null : string.Join(',', macs);
    }

    /// <summary>Unknown on either side means "cannot tell apart" – the networks are treated as the same.</summary>
    public static bool SameNetwork(string? a, string? b) =>
        a is null || b is null || a.Split(',').Intersect(b.Split(',')).Any();
}
