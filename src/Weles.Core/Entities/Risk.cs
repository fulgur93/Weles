using Weles.Core.Enums;

namespace Weles.Core.Entities;

/// <summary>
/// A configuration weakness found by a rule (<see cref="Risk.RiskRules"/>). One record per device, rule and port: later
/// scans update it, resolve it when the evidence disappears and reopen it when it comes back.
/// </summary>
public class RiskFinding
{
    public int Id { get; set; }

    /// <summary>Latest scan that confirmed (or resolved) the finding.</summary>
    public int ScanId { get; set; }
    public Scan? Scan { get; set; }
    public int AssetId { get; set; }
    public Asset? Asset { get; set; }

    /// <summary>Identifier of the rule that produced the finding, e.g. "EXPOSED-SMB".</summary>
    public required string RuleId { get; set; }
    public required string Title { get; set; }
    public string? Description { get; set; }
    public required string Category { get; set; }
    public RiskLevel Level { get; set; }
    public double Score { get; set; }
    public string? Evidence { get; set; }
    public string? Recommendation { get; set; }
    public FindingStatus Status { get; set; }

    /// <summary>Port the rule fired on; null for device-level findings.</summary>
    public int? Port { get; set; }

    /// <summary>0–100: how sure the evidence is (an open port recognised only by number is less certain).</summary>
    public int Confidence { get; set; }

    /// <summary>MITRE ATT&amp;CK technique IDs, comma-separated.</summary>
    public string? AttackTechniques { get; set; }

    /// <summary>First detection.</summary>
    public DateTime CreatedAt { get; set; }
    public DateTime LastDetectedAt { get; set; }
    public DateTime? ResolvedAt { get; set; }
}

/// <summary>
/// Score for a single asset in a scan, or – when <see cref="AssetId"/> is null – the overall Security Posture Score.
/// </summary>
public class RiskScore
{
    public int Id { get; set; }
    public int ScanId { get; set; }
    public Scan? Scan { get; set; }
    public int? AssetId { get; set; }
    public Asset? Asset { get; set; }

    public double Score { get; set; }
    public RiskLevel Level { get; set; }

    /// <summary>Every factor that contributed to the score – the score is never shown without its reasons.</summary>
    public required string BreakdownJson { get; set; }
    public DateTime CalculatedAt { get; set; }
}
