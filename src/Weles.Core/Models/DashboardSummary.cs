using Weles.Core.Enums;

namespace Weles.Core.Models;

public sealed record DashboardSummary(
    int AssetCount,
    int ActiveServiceCount,
    int VulnerabilityCount,
    int CriticalFindingCount,
    int NewAssetsSinceLastScan,
    int CompletedScanCount,
    LastScanInfo? LastScan,
    double? SecurityPostureScore,
    DateTime? VulnerabilityDatabaseUpdatedAt)
{
    public bool HasAnyScan => CompletedScanCount > 0;
}

public sealed record LastScanInfo(int Id, string TargetName, ScanStatus Status, DateTime? StartedAt, DateTime? CompletedAt, int HostsAlive, int OpenPorts);
