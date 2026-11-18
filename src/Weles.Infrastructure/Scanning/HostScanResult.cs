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
    IReadOnlyList<PortScanResult> OpenPorts);
