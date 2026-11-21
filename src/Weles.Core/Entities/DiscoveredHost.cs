using Weles.Core.Enums;

namespace Weles.Core.Entities;

/// <summary>Immutable snapshot of a host as observed in a single scan.</summary>
public class DiscoveredHost
{
    public int Id { get; set; }
    public int ScanId { get; set; }
    public Scan? Scan { get; set; }

    public int? AssetId { get; set; }
    public Asset? Asset { get; set; }

    public required string IpAddress { get; set; }
    public string? Hostname { get; set; }
    public string? MacAddress { get; set; }
    public string? Vendor { get; set; }
    public DiscoveryMethod DiscoveryMethods { get; set; }
    public double? RoundTripMs { get; set; }
    public int? Ttl { get; set; }
    public string? OsGuess { get; set; }
    public bool IsGateway { get; set; }
    public AssetType AssetTypeGuess { get; set; }
    public int ClassificationConfidence { get; set; }

    /// <summary>Newline-separated reasons behind the OS/type guess.</summary>
    public string? ClassificationReasons { get; set; }

    /// <summary>Services the device advertises over mDNS/DNS-SD (JSON array of {Type, Instance, Port}).</summary>
    public string? AnnouncedServicesJson { get; set; }
    public DateTime DiscoveredAt { get; set; }

    public List<DiscoveredPort> Ports { get; set; } = [];
}

public class DiscoveredPort
{
    public int Id { get; set; }
    public int DiscoveredHostId { get; set; }
    public DiscoveredHost? Host { get; set; }

    public int Port { get; set; }
    public TransportProtocol Protocol { get; set; }
    public PortState State { get; set; }

    /// <summary>Why the state was assigned, e.g. "syn-ack", "timeout", "reset".</summary>
    public string? Reason { get; set; }

    public DiscoveredService? Service { get; set; }
}

public class DiscoveredService
{
    public int Id { get; set; }
    public int DiscoveredPortId { get; set; }
    public DiscoveredPort? Port { get; set; }

    public string? ServiceName { get; set; }
    public string? Product { get; set; }
    public string? Vendor { get; set; }
    public string? Version { get; set; }
    public string? Cpe { get; set; }
    public string? Banner { get; set; }

    /// <summary>Identification confidence 0–100. Port number alone never yields a version.</summary>
    public int Confidence { get; set; }
    public string? DetectionMethod { get; set; }
    public bool IsTls { get; set; }
    public string? ExtraInfoJson { get; set; }

    /// <summary>The HTTP(S) observation (<see cref="Fingerprint.WebObservation"/>) as JSON – signatures are evaluated on it.</summary>
    public string? WebJson { get; set; }

    public List<ServiceTechnology> Technologies { get; set; } = [];

    public List<Certificate> Certificates { get; set; } = [];
}

public class Certificate
{
    public int Id { get; set; }
    public int DiscoveredServiceId { get; set; }
    public DiscoveredService? Service { get; set; }

    public required string Subject { get; set; }
    public required string Issuer { get; set; }
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public required string Thumbprint { get; set; }
    public string? SerialNumber { get; set; }
    public string? SubjectAlternativeNames { get; set; }
    public string? KeyAlgorithm { get; set; }
    public int? KeySize { get; set; }
    public string? SignatureAlgorithm { get; set; }
    public string? TlsProtocol { get; set; }
    public bool IsSelfSigned { get; set; }
    public bool? HostnameMatches { get; set; }
}
