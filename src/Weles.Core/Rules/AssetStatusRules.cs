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

public sealed record AssetPresence(AssetStatus Status, int? ReferenceScanId, DateTime? ReferenceScanAt);

/// <summary>
/// Presence of an asset is judged against the latest completed scan that covered its address (or observed it).
/// A device missing from a scan that never looked at its address is not "missing".
/// </summary>
public static class AssetStatusRules
{
    /// <param name="completedScans">Completed scans, newest first.</param>
    /// <param name="observedInScans">Scans in which the asset was observed.</param>
    /// <param name="firstObservedScanId">Scan of the asset's first observation.</param>
    /// <param name="assetNetwork">Network of the asset's latest observation; scans of another network do not count.</param>
    public static AssetPresence Evaluate(string? ipAddress, IReadOnlyList<CompletedScanCoverage> completedScans, IReadOnlySet<int> observedInScans, int? firstObservedScanId, string? assetNetwork = null)
    {
        foreach (var scan in completedScans)
        {
            var observed = observedInScans.Contains(scan.ScanId);
            if (!observed && !scan.Covers(ipAddress, assetNetwork)) continue;

            var status = !observed ? AssetStatus.Missing : scan.ScanId == firstObservedScanId ? AssetStatus.New : AssetStatus.Active;
            return new AssetPresence(status, scan.ScanId, scan.StartedAt);
        }

        return new AssetPresence(AssetStatus.NotCovered, null, null);
    }

    /// <summary>Covering scans (newest first) in which the asset was not found – the gaps in its history.</summary>
    /// <param name="firstObservedScanAt">Start of the scan in which the asset was first observed – earlier scans are not gaps.</param>
    public static IEnumerable<CompletedScanCoverage> Absences(string? ipAddress, IReadOnlyList<CompletedScanCoverage> completedScans, IReadOnlySet<int> observedInScans, DateTime firstObservedScanAt, string? assetNetwork = null) =>
        completedScans.Where(s => s.StartedAt > firstObservedScanAt && !observedInScans.Contains(s.ScanId) && s.Covers(ipAddress, assetNetwork));
}
