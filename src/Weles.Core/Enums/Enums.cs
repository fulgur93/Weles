namespace Weles.Core.Enums;

public enum ScanStatus
{
    Pending = 0,
    Running = 1,
    Completed = 2,
    Cancelled = 3,
    Failed = 4,
    /// <summary>Stopped at the end of its time window; resumes from the next subgroup in the next window.</summary>
    Paused = 5
}

public enum ScanTrigger
{
    Manual = 0,
    Scheduled = 1,
    Agent = 2,
    /// <summary>Results imported from a file (nmap XML, CSV, JSON) – no traffic was sent by WELES.</summary>
    Import = 3
}

public enum ScanTargetEntryKind
{
    IpAddress = 0,
    Cidr = 1,
    IpRange = 2,
    Domain = 3
}

public enum TransportProtocol
{
    Tcp = 0,
    Udp = 1
}

public enum PortState
{
    Open = 0,
    Closed = 1,
    Filtered = 2
}

[Flags]
public enum DiscoveryMethod
{
    None = 0,
    Icmp = 1,
    TcpConnect = 2,
    Arp = 4,
    Dns = 8,
    Agent = 16,
    Mdns = 32
}

public enum AssetType
{
    Unknown = 0,
    WindowsHost = 1,
    LinuxHost = 2,
    Server = 3,
    Router = 4,
    Switch = 5,
    Printer = 6,
    IpCamera = 7,
    IoTDevice = 8,
    VirtualMachine = 9,
    Nas = 10,
    NetworkDevice = 11,
    MobileDevice = 12
}

/// <summary>Business criticality of an asset, set by the user (default Medium).</summary>
public enum AssetCriticality
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>Presence of an asset relative to the latest completed scan that covered its address.</summary>
public enum AssetStatus
{
    /// <summary>First observed in that scan.</summary>
    New = 0,
    /// <summary>Observed in that scan and earlier.</summary>
    Active = 1,
    /// <summary>The scan covered its address but did not find it.</summary>
    Missing = 2,
    /// <summary>No completed scan covered its address.</summary>
    NotCovered = 3,
    /// <summary>Last judged on its own network, but a later scan ran on another network – its current state is unknown.</summary>
    Unknown = 4,
    /// <summary>Did not answer the latest covering scan(s), fewer times in a row than the inactivity threshold – may be off or unstable.</summary>
    Intermittent = 5
}

public enum AssetChangeKind
{
    AddressChanged,
    HostnameChanged,
    MacChanged,
    PortOpened,
    PortClosed,
    ServiceChanged,
    VersionChanged,
    CertificateChanged,
    TypeChanged
}

public enum RiskLevel
{
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>How strongly a discovered software version matches a known vulnerability.</summary>
public enum VulnerabilityMatchStatus
{
    Confirmed = 0,
    Probable = 1,
    NeedsVerification = 2,
    InsufficientData = 3
}

public enum FindingStatus
{
    Open = 0,
    Resolved = 1,
    Accepted = 2
}

public enum ReportFormat
{
    Pdf = 0,
    Json = 1,
    Zip = 2
}

public enum AgentStatus
{
    /// <summary>Created, waiting for the agent to enroll with its one-time code.</summary>
    Pending = 0,
    Active = 1,
    Revoked = 2
}
