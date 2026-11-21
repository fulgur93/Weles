using Weles.Core.Enums;

namespace Weles.Core.Entities;

public class Scan
{
    public int Id { get; set; }
    public int ScanTargetId { get; set; }
    public ScanTarget? ScanTarget { get; set; }

    public ScanStatus Status { get; set; }
    public ScanTrigger Trigger { get; set; }

    /// <summary>Port specification used for this scan, e.g. "top100" or "22,80,443,8000-8100".</summary>
    public required string PortSpecification { get; set; }

    public DateTime CreatedAt { get; set; }
    public DateTime? StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }

    /// <summary>Number of addresses in the resolved scope at scan time.</summary>
    public int HostsTargeted { get; set; }
    public int HostsProbed { get; set; }
    public int PortCount { get; set; }

    /// <summary>Scope entries as they were when the scan started – the target may be edited later.</summary>
    public string? ScopeSnapshot { get; set; }

    /// <summary>MAC address(es) of the scanned network's gateway – tells apart networks that reuse the same private range.</summary>
    public string? NetworkFingerprint { get; set; }

    /// <summary>Limits (concurrency, rate, timeouts) used for this scan.</summary>
    public string? SettingsJson { get; set; }

    public int HostsAlive { get; set; }
    public int OpenPorts { get; set; }
    public string? ErrorMessage { get; set; }

    public bool IsDemo { get; set; }

    /// <summary>The remote agent that runs this scan (Trigger = Agent); null for scans run by WELES itself.</summary>
    public int? AgentId { get; set; }
    public Agent? Agent { get; set; }

    public List<DiscoveredHost> Hosts { get; set; } = [];
    public List<ScanEvent> Events { get; set; } = [];
    public List<RiskFinding> Findings { get; set; } = [];
    public List<RiskScore> RiskScores { get; set; } = [];
}
