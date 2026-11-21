namespace Weles.Core.Entities;

/// <summary>
/// Roles (the AGH requirement): Admin – everything incl. users, settings, agents, integrations; Editor – add, delete and
/// modify (scopes, signatures, imports, reports); Operator – modify existing data and run scans; Viewer – read and export.
/// </summary>
public enum UserRole
{
    Admin = 0,
    Editor = 1,
    Operator = 2,
    Viewer = 3
}

/// <summary>A user of the WELES panel. The password is stored only as a PBKDF2-SHA256 hash.</summary>
public class AppUser
{
    public int Id { get; set; }
    public required string UserName { get; set; }
    public required string PasswordHash { get; set; }
    public UserRole Role { get; set; }
    public bool Disabled { get; set; }

    /// <summary>Changes on every role or password change – sessions issued before are rejected.</summary>
    public required string SecurityStamp { get; set; }
    public int FailedLogins { get; set; }
    public DateTime? LockedUntil { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
}
