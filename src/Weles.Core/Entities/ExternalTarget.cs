namespace Weles.Core.Entities;

public enum ExternalTargetKind
{
    Domain = 0,
    Address = 1
}

public enum ExternalAnalysisStatus
{
    Running = 0,
    Completed = 1,
    Failed = 2
}

/// <summary>
/// A domain or public address the user declared as theirs (or authorised in writing). Passive analysis uses public
/// sources only; active scanning needs a separate scope with its own approval and permission for public addresses.
/// </summary>
public class ExternalTarget
{
    public int Id { get; set; }
    public required string Name { get; set; }
    public ExternalTargetKind Kind { get; set; }
    public string? Description { get; set; }

    /// <summary>The user confirmed ownership or written permission when adding the target.</summary>
    public DateTime AuthorizedAt { get; set; }

    /// <summary>Query Certificate Transparency logs (crt.sh) – sends the domain name to that public service.</summary>
    public bool UseCertificateTransparency { get; set; }

    /// <summary>Extra host names the user knows (one per line); they are resolved like names from CT.</summary>
    public string? KnownHosts { get; set; }

    /// <summary>Scope created for active scanning of selected hosts; null until the user asks for it.</summary>
    public int? ScanTargetId { get; set; }
    public ScanTarget? ScanTarget { get; set; }

    public DateTime CreatedAt { get; set; }
    public List<ExternalAnalysis> Analyses { get; set; } = [];
}

/// <summary>One passive analysis run; the collected data is kept as a JSON snapshot.</summary>
public class ExternalAnalysis
{
    public int Id { get; set; }
    public int ExternalTargetId { get; set; }
    public ExternalTarget? ExternalTarget { get; set; }
    public ExternalAnalysisStatus Status { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
    public string? SnapshotJson { get; set; }
    public int HostCount { get; set; }
    public int FindingCount { get; set; }
    public string? Error { get; set; }
}
