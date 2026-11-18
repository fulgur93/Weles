using Weles.Core.Enums;

namespace Weles.Core.Entities;

/// <summary>
/// Stable identity of a device across scans. Per-scan observations live in <see cref="DiscoveredHost"/>.
/// </summary>
public class Asset
{
    public int Id { get; set; }
    public required string DisplayName { get; set; }
    public string? Hostname { get; set; }
    public string? PrimaryIpAddress { get; set; }
    public string? MacAddress { get; set; }
    public string? Vendor { get; set; }
    public AssetType AssetType { get; set; }
    public string? OsFamily { get; set; }
    public string? OsDetails { get; set; }
    public AssetCriticality Criticality { get; set; } = AssetCriticality.Medium;
    public string? Notes { get; set; }
    public string? ClassificationReasons { get; set; }

    public int? NetworkSegmentId { get; set; }
    public NetworkSegment? NetworkSegment { get; set; }

    public double? CurrentRiskScore { get; set; }
    public RiskLevel? CurrentRiskLevel { get; set; }

    public DateTime FirstSeenAt { get; set; }
    public DateTime LastSeenAt { get; set; }
    public bool IsDemo { get; set; }

    public List<DiscoveredHost> Observations { get; set; } = [];
    public List<AssetVulnerability> Vulnerabilities { get; set; } = [];
}
