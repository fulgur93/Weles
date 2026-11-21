using Weles.Core.Fingerprint;

namespace Weles.Core.Entities;

/// <summary>A technology (CMS, framework, server, panel, staging…) a signature found on a web service in one scan.</summary>
public class ServiceTechnology
{
    public int Id { get; set; }
    public int DiscoveredServiceId { get; set; }
    public DiscoveredService? Service { get; set; }

    public required string SignatureId { get; set; }
    public required string Name { get; set; }
    public SignatureCategory Category { get; set; }
    public string? Version { get; set; }
    public int Confidence { get; set; }

    /// <summary>MITRE CWE from the signature, if it has one.</summary>
    public int? Cwe { get; set; }

    /// <summary>Why the signature matched, one line per condition.</summary>
    public string? Evidence { get; set; }
}

/// <summary>A signature added by the user (JSON in the <see cref="Signature"/> format). Built-in signatures live in code.</summary>
public class CustomSignature
{
    public int Id { get; set; }
    public required string SignatureId { get; set; }
    public required string Json { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }
}
