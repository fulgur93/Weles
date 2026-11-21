using System.Net;
using Weles.Core.Enums;
using Weles.Core.Rules;

namespace Weles.Infrastructure.Scanning;

public sealed record PortScanResult(int Port, string Reason, ServiceProbeResult? Service);

public sealed record HostScanResult(
    IPAddress Address,
    DiscoveryMethod Methods,
    double? RoundTripMs,
    int? Ttl,
    string? Hostname,
    string? MacAddress,
    string? Vendor,
    bool IsGateway,
    HostClassification Classification,
    IReadOnlyList<PortScanResult> OpenPorts,
    IReadOnlyList<MdnsService>? AnnouncedServices = null,
    IReadOnlySet<string>? LocalMacAddresses = null,
    IReadOnlyList<string>? TracePath = null)
{
    /// <summary>The machine running WELES, reached on a network address (not loopback).</summary>
    public bool IsLocalMachine => LocalMacAddresses is not null;
}
