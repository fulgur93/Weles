namespace Weles.Infrastructure.Scanning;

/// <summary>Safety limits for active scanning. Bound from "Weles:Scanning".</summary>
public sealed class ScanOptions
{
    public const string SectionName = "Weles:Scanning";

    public int MaxHostsPerScan { get; set; } = 4096;

    /// <summary>Upper bound of simultaneously open TCP connections across the whole scan.</summary>
    public int MaxConcurrentConnections { get; set; } = 200;

    /// <summary>New connection attempts per second (token bucket).</summary>
    public int ConnectionsPerSecond { get; set; } = 400;

    public int ParallelHostDiscovery { get; set; } = 64;
    public int ParallelHostScans { get; set; } = 8;
    public int ParallelServiceProbesPerHost { get; set; } = 6;

    public int ConnectTimeoutMs { get; set; } = 1200;
    public int PingTimeoutMs { get; set; } = 1000;
    public int BannerTimeoutMs { get; set; } = 2500;
    public int ProbeTimeoutMs { get; set; } = 4000;
    public int DnsTimeoutMs { get; set; } = 2000;

    public bool UseIcmp { get; set; } = true;

    /// <summary>TCP ports used to decide whether a host is alive when ICMP is blocked.</summary>
    public int[] LivenessPorts { get; set; } = [22, 53, 80, 135, 139, 443, 445, 3389, 8080];
}
