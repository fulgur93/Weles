using Weles.Core.Enums;

namespace Weles.Core.Entities;

/// <summary>
/// An explicitly defined and user-approved scope. Every scan must reference one.
/// </summary>
public class ScanTarget
{
    public int Id { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }

    /// <summary>Scans are refused unless the scope was approved by the user.</summary>
    public bool IsApproved { get; set; }
    public DateTime? ApprovedAt { get; set; }

    /// <summary>Public (non-RFC1918) addresses require an explicit, separate permission.</summary>
    public bool AllowPublicAddresses { get; set; }

    /// <summary>
    /// Scope of public (Internet) hosts prepared in the Attack Surface module. Its scans are reported there and never
    /// mixed into the local network's posture, monitoring defaults or topology.
    /// </summary>
    public bool IsExternal { get; set; }

    public bool IsDemo { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    public List<ScanTargetEntry> Entries { get; set; } = [];
    public List<Scan> Scans { get; set; } = [];
}

public class ScanTargetEntry
{
    public int Id { get; set; }
    public int ScanTargetId { get; set; }
    public ScanTarget? ScanTarget { get; set; }

    /// <summary>IP, CIDR, range (a.b.c.d-e.f.g.h) or domain name.</summary>
    public required string Value { get; set; }
    public ScanTargetEntryKind Kind { get; set; }

    /// <summary>When true the entry is excluded from the scope (deny wins over allow).</summary>
    public bool IsExclusion { get; set; }
}
