namespace Weles.Infrastructure.Scanning;

/// <summary>Safety limits for active scanning. Bound from "Weles:Scanning".</summary>
public sealed class ScanOptions
{
    public const string SectionName = "Weles:Scanning";

    /// <summary>Largest scope one scan may cover (a /16 – the AGH requirement is above 10 000 addresses). Scopes still need approval.</summary>
    public int MaxHostsPerScan { get; set; } = 65536;

    /// <summary>Upper bound of simultaneously open TCP connections across the whole scan.</summary>
    public int MaxConcurrentConnections { get; set; } = 200;

    /// <summary>New connection attempts per second (token bucket).</summary>
    public int ConnectionsPerSecond { get; set; } = 400;

    /// <summary>
    /// New connection attempts per second to a single host. Consumer routers treat bursts of SYNs as a flood: a TP-Link
    /// TL-WR841N stopped answering its own web services for over 10 minutes after ~1000 connections at 400/s.
    /// </summary>
    public int ConnectionsPerSecondPerHost { get; set; } = 20;

    /// <summary>Simultaneously open connections to a single host.</summary>
    public int MaxConcurrentConnectionsPerHost { get; set; } = 10;

    public int ParallelHostDiscovery { get; set; } = 64;
    public int ParallelHostScans { get; set; } = 8;
    public int ParallelServiceProbesPerHost { get; set; } = 6;

    public int ConnectTimeoutMs { get; set; } = 1200;
    public int PingTimeoutMs { get; set; } = 1000;
    public int BannerTimeoutMs { get; set; } = 2500;
    public int ProbeTimeoutMs { get; set; } = 4000;
    public int DnsTimeoutMs { get; set; } = 2000;

    public bool UseIcmp { get; set; } = true;

    /// <summary>Ask the local segment over mDNS/DNS-SD which services devices advertise (finds e.g. Android wireless debugging).</summary>
    public bool UseMdns { get; set; } = true;
    public int MdnsListenMs { get; set; } = 3000;

    /// <summary>
    /// HTTP(S) services: record headers, cookies (names and flags), the redirect chain, the favicon hash and a few safe GET
    /// paths for signature detection. Only plain GETs – no parameters, no form data, no credentials.
    /// </summary>
    public bool CollectWeb { get; set; } = true;

    /// <summary>Well-known paths requested on every web service (signatures can add more; at most 16 in total).</summary>
    public string[] WebProbePaths { get; set; } = ["/robots.txt", "/admin", "/login", "/wp-login.php", "/administrator/", "/version", "/actuator/health", "/manager/html"];

    /// <summary>TCP ports used to decide whether a host is alive when ICMP is blocked.</summary>
    public int[] LivenessPorts { get; set; } = [22, 53, 80, 135, 139, 443, 445, 3389, 8080];
}
