using Weles.Core.Enums;

namespace Weles.Core.Entities;

/// <summary>
/// A remote scanning agent. It connects out to WELES over HTTPS, may scan only the scopes assigned to it here, and holds
/// a token that WELES stores only as a SHA-256 hash. Revoking it invalidates the token at once.
/// </summary>
public class Agent
{
    public int Id { get; set; }
    public required string Name { get; set; }
    public AgentStatus Status { get; set; }
    public DateTime CreatedAt { get; set; }

    /// <summary>SHA-256 of the one-time enrollment code; cleared when the agent enrolls.</summary>
    public string? EnrollmentCodeHash { get; set; }
    public DateTime? EnrollmentExpiresAt { get; set; }
    public DateTime? EnrolledAt { get; set; }

    /// <summary>SHA-256 of the access token – the token itself is never stored.</summary>
    public string? TokenHash { get; set; }

    public DateTime? LastSeenAt { get; set; }

    /// <summary>Address the agent last connected from.</summary>
    public string? LastAddress { get; set; }
    public string? Hostname { get; set; }
    public string? OperatingSystem { get; set; }
    public string? AgentVersion { get; set; }

    /// <summary>System information and network interfaces reported by the agent (JSON).</summary>
    public string? SystemInfoJson { get; set; }
    public DateTime? RevokedAt { get; set; }

    public List<AgentScope> Scopes { get; set; } = [];
}

/// <summary>A scope the agent may scan. Nothing outside these scopes is ever sent to it.</summary>
public class AgentScope
{
    public int AgentId { get; set; }
    public Agent? Agent { get; set; }
    public int ScanTargetId { get; set; }
    public ScanTarget? ScanTarget { get; set; }
}
