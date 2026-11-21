using Weles.Core.Enums;
using Weles.Core.Networking;

namespace Weles.Core.Rules;

/// <param name="Network">Gateway fingerprint of the scanned network (<see cref="NetworkIdentity"/>), null when unknown.</param>
public sealed record CompletedScanCoverage(int ScanId, DateTime StartedAt, ScopeCoverage Coverage, string? Network = null)
{
    /// <summary>The scan looked at this address on the network where the asset lives.</summary>
    public bool Covers(string? ipAddress, string? assetNetwork) =>
        Coverage.Covers(ipAddress) && NetworkIdentity.SameNetwork(Network, assetNetwork);
}

/// <param name="ConsecutiveMisses">Covering scans in a row (newest first) without an answer.</param>
public sealed record AssetPresence(AssetStatus Status, int? ReferenceScanId, DateTime? ReferenceScanAt, int ConsecutiveMisses = 0);

/// <summary>
/// Presence of an asset is judged against the latest completed scan that covered its address (or observed it).
/// A device missing from a scan that never looked at its address is not "missing". When a scan of another identified
/// network ran after that, the asset is <see cref="AssetStatus.Unknown"/> – it was left behind on a network the user is no longer on.
/// </summary>
public static class AssetStatusRules
{
    /// <param name="completedScans">Completed scans, newest first.</param>
    /// <param name="observedInScans">Scans in which the asset was observed.</param>
    /// <param name="firstObservedScanId">Scan of the asset's first observation.</param>
    /// <param name="assetNetwork">Network of the asset's latest observation; scans of another network do not count.</param>
    /// <param name="inactiveAfterMisses">A host that answered before becomes <see cref="AssetStatus.Missing"/> only after this many
    /// covering scans in a row without an answer; fewer misses make it <see cref="AssetStatus.Intermittent"/> (one silent
    /// scan of a host that answers at other times of day is not a disappearance).</param>
    public static AssetPresence Evaluate(string? ipAddress, IReadOnlyList<CompletedScanCoverage> completedScans, IReadOnlySet<int> observedInScans, int? firstObservedScanId,
        string? assetNetwork = null, int inactiveAfterMisses = PresenceHistory.DefaultInactiveAfterMisses)
    {
        var laterScanOfAnotherNetwork = false;
        var misses = 0;
        CompletedScanCoverage? reference = null;
        foreach (var scan in completedScans)
        {
            var observed = observedInScans.Contains(scan.ScanId);
            if (!observed && !scan.Covers(ipAddress, assetNetwork))
            {
                if (reference is null) laterScanOfAnotherNetwork |= IsAnotherNetwork(scan.Network, assetNetwork);
                continue;
            }

            reference ??= scan;
            if (!observed)
            {
                misses++;
                continue;
            }

            // The user has since moved to (and scanned) another network: what was true here is no longer confirmed.
            var status = laterScanOfAnotherNetwork ? AssetStatus.Unknown
                : misses >= inactiveAfterMisses ? AssetStatus.Missing
                : misses > 0 ? AssetStatus.Intermittent
                : scan.ScanId == firstObservedScanId ? AssetStatus.New
                : AssetStatus.Active;
            return new AssetPresence(status, reference.ScanId, reference.StartedAt, misses);
        }

        // Covered but never observed in any covering scan (e.g. observed only by a scan that is not "completed").
        return reference is null
            ? new AssetPresence(AssetStatus.NotCovered, null, null)
            : new AssetPresence(laterScanOfAnotherNetwork ? AssetStatus.Unknown : AssetStatus.Missing, reference.ScanId, reference.StartedAt, misses);
    }

    /// <summary>Both networks identified and different. An unidentified scan (loopback, routed subnet) says nothing.</summary>
    private static bool IsAnotherNetwork(string? scanNetwork, string? assetNetwork) =>
        scanNetwork is not null && assetNetwork is not null && !NetworkIdentity.SameNetwork(scanNetwork, assetNetwork);

    /// <summary>Covering scans (newest first) in which the asset was not found – the gaps in its history.</summary>
    /// <param name="firstObservedScanAt">Start of the scan in which the asset was first observed – earlier scans are not gaps.</param>
    public static IEnumerable<CompletedScanCoverage> Absences(string? ipAddress, IReadOnlyList<CompletedScanCoverage> completedScans, IReadOnlySet<int> observedInScans, DateTime firstObservedScanAt, string? assetNetwork = null) =>
        completedScans.Where(s => s.StartedAt > firstObservedScanAt && !observedInScans.Contains(s.ScanId) && s.Covers(ipAddress, assetNetwork));
}
