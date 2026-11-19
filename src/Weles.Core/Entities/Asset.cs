using Weles.Core.Enums;

namespace Weles.Core.Entities;

/// <summary>
/// Stable identity of a device across scans. Per-scan observations live in <see cref="DiscoveredHost"/>.
/// </summary>
public class Asset
{
    public int Id { get; set; }
    /// <summary>Name shown in the UI: <see cref="CustomName"/> if set, otherwise derived from scan data.</summary>
    public required string DisplayName { get; set; }

    /// <summary>Name given by the user (e.g. "Telefon Xiaomi"). Scans never overwrite it.</summary>
    public string? CustomName { get; set; }
    public string? Hostname { get; set; }
    public string? PrimaryIpAddress { get; set; }
    public string? MacAddress { get; set; }
    public string? Vendor { get; set; }
    /// <summary>Type detected by the classifier (updated by every scan).</summary>
    public AssetType AssetType { get; set; }

    /// <summary>Type set by the user; takes precedence over <see cref="AssetType"/> and is never overwritten by scans.</summary>
    public AssetType? UserAssetType { get; set; }

    public AssetType EffectiveType => UserAssetType ?? AssetType;
    public string? OsFamily { get; set; }
    public string? OsDetails { get; set; }

    /// <summary>Hardware model the device disclosed itself (HTTP realm, UPnP header, ADB), e.g. "TP-Link TL-WR841N".</summary>
    public string? Model { get; set; }
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
