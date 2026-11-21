using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Scanning;

namespace Weles.Infrastructure.Agents;

/// <summary>
/// The agent ↔ WELES protocol (version 1). The agent always starts the connection (HTTPS, server certificate pinned by
/// its SHA-256); WELES never connects to the agent. Four calls only:
/// <list type="bullet">
/// <item><c>POST enroll</c> – one-time enrollment code → access token.</item>
/// <item><c>POST heartbeat</c> – status and system information; the answer may carry a scan job.</item>
/// <item><c>POST scans/{id}/results</c> – a batch of hosts and events of the agent's own running scan.</item>
/// <item><c>POST scans/{id}/complete</c> – the scan ended (completed, failed, cancelled).</item>
/// </list>
/// The agent can read nothing else from WELES: no inventory, no other scans, no settings.
/// </summary>
public static class AgentProtocol
{
    public const string Prefix = "/agent-api/v1";
    public const string EnrollPath = Prefix + "/enroll";
    public const string HeartbeatPath = Prefix + "/heartbeat";
    public static string ResultsPath(int scanId) => $"{Prefix}/scans/{scanId}/results";
    public static string CompletePath(int scanId) => $"{Prefix}/scans/{scanId}/complete";

    /// <summary>Largest request body accepted from an agent.</summary>
    public const int MaxBodyBytes = 8 * 1024 * 1024;
    public const int MaxHostsPerUpload = 64;
    public const int MaxEventsPerUpload = 20;
    public const int PollSeconds = 30;

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
        MaxDepth = 32
    };

    /// <summary>"sha256 of the certificate (DER)" as lowercase hex – what the agent pins.</summary>
    public static string Pin(byte[] certificateDer) => Convert.ToHexStringLower(SHA256.HashData(certificateDer));

    /// <summary>Pins are compared case- and separator-insensitively ("AB:CD…" = "abcd…").</summary>
    public static string NormalizePin(string pin) => new string(pin.Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
}

public sealed record AgentInterface(string Name, string Type, string Address, int PrefixLength, string NetworkCidr, string? Gateway, string? MacAddress);

public sealed record AgentSystemInfo(string Hostname, string OperatingSystem, string Architecture, string AgentVersion, int ProcessorCount, IReadOnlyList<AgentInterface> Interfaces);

public sealed record EnrollRequest(string Code, AgentSystemInfo System);

public sealed record EnrollResponse(int AgentId, string Name, string Token);

/// <param name="RunningScanId">The scan the agent is working on now, if any.</param>
public sealed record HeartbeatRequest(AgentSystemInfo System, int? RunningScanId);

/// <param name="Job">A scan to run now (only when the agent is idle).</param>
/// <param name="CancelRunning">Stop the running scan – the user stopped it or WELES no longer expects it.</param>
public sealed record HeartbeatResponse(string Name, int PollSeconds, AgentJob? Job, bool CancelRunning);

/// <summary>A scan of an approved scope assigned to this agent. Entries are IP addresses, CIDRs and ranges only.</summary>
public sealed record AgentJob(int ScanId, string ScopeName, IReadOnlyList<ScopeEntry> Entries, string PortSpecification);

/// <summary>One scanned host as the agent sends it (an IP address as text; the rest mirrors <see cref="HostScanResult"/>).</summary>
/// <param name="IsAgentMachine">The host is the machine running the agent.</param>
public sealed record AgentHost(
    string Address,
    DiscoveryMethod Methods,
    double? RoundTripMs,
    int? Ttl,
    string? Hostname,
    string? MacAddress,
    bool IsGateway,
    HostClassification Classification,
    IReadOnlyList<PortScanResult> OpenPorts,
    IReadOnlyList<MdnsService>? AnnouncedServices,
    bool IsAgentMachine);

public sealed record AgentEvent(ScanEventLevel Level, string Message);

/// <summary>What the agent knows about its scan so far – sent with every batch.</summary>
public sealed record AgentScanState(int HostsTargeted, int HostsProbed, int PortCount, string? NetworkFingerprint, IReadOnlyList<SegmentInfo>? Segments);

public sealed record ResultsRequest(IReadOnlyList<AgentHost> Hosts, IReadOnlyList<AgentEvent> Events, AgentScanState State);

/// <param name="Cancel">The user stopped the scan – finish with status Cancelled.</param>
public sealed record ResultsResponse(int Accepted, int Rejected, bool Cancel);

/// <param name="Error">Why the scan failed (Status = Failed).</param>
public sealed record CompleteRequest(ScanStatus Status, string? Error, IReadOnlyList<AgentEvent> Events, AgentScanState State);
