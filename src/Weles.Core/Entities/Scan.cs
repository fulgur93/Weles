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

    public int HostsAlive { get; set; }
    public int OpenPorts { get; set; }
    public string? ErrorMessage { get; set; }

    public bool IsDemo { get; set; }

    public List<DiscoveredHost> Hosts { get; set; } = [];
    public List<RiskFinding> Findings { get; set; } = [];
    public List<RiskScore> RiskScores { get; set; } = [];
}
