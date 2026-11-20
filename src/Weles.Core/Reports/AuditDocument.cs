using System.Text.Json;
using System.Text.Json.Serialization;
using Weles.Core.Enums;
using Weles.Core.Risk;

namespace Weles.Core.Reports;

/// <summary>
/// Everything one audit (a completed scan) established, frozen at export time: scope, devices, services,
/// vulnerabilities, risk, recommendations, changes since the previous audit of the same network and the AI summary.
/// The same document feeds the PDF report, the JSON/ZIP export and the viewer of imported audits, so an audit opened
/// on another computer shows exactly what the original showed. Texts are stored in Polish, as WELES generates them.
/// </summary>
public sealed record AuditDocument(
    string Format,
    int SchemaVersion,
    DateTime ExportedAt,
    string GeneratedBy,
    AuditInfo Audit,
    AuditPosture? Posture,
    IReadOnlyList<AuditDevice> Devices,
    IReadOnlyList<AuditRecommendation> Recommendations,
    AuditChanges? Changes,
    AuditAiSummaryInfo? AiSummary)
{
    public const string FormatName = "weles-audit";
    public const int CurrentSchemaVersion = 1;

    [JsonIgnore]
    public int ServiceCount => Devices.Sum(d => d.Services.Count);

    [JsonIgnore]
    public int VulnerabilityCount => Devices.Sum(d => d.Vulnerabilities.Count(v => v.Status == FindingStatus.Open));

    [JsonIgnore]
    public int KnownExploitedCount => Devices.Sum(d => d.Vulnerabilities.Count(v => v.Status == FindingStatus.Open && v.IsKnownExploited));

    [JsonIgnore]
    public IReadOnlyDictionary<RiskLevel, int> DevicesByLevel =>
        Devices.Where(d => d.RiskLevel is not null).GroupBy(d => d.RiskLevel!.Value).ToDictionary(g => g.Key, g => g.Count());
}

/// <param name="Scope">Scope entries at scan time ("192.168.0.0/24", "wyklucz 192.168.0.10").</param>
/// <param name="Network">Network the audit describes, e.g. "192.168.0.0/24 – router TP-LINK".</param>
/// <param name="IsExternal">Scan of public hosts (Attack Surface) – reachability was observed over the Internet.</param>
public sealed record AuditInfo(
    int ScanId,
    string ScopeName,
    IReadOnlyList<string> Scope,
    string Network,
    bool IsExternal,
    DateTime StartedAt,
    DateTime? CompletedAt,
    string PortSpecification,
    ScanTrigger Trigger,
    int HostsTargeted,
    int HostsAlive,
    int OpenPorts,
    bool IsDemo);

public sealed record AuditPosture(double Score, double? Previous, IReadOnlyList<RiskFactor> Factors);

public sealed record AuditDevice(
    string Name,
    string? Ip,
    string? Hostname,
    string? Mac,
    string? Vendor,
    AssetType Type,
    string? Os,
    string? Model,
    AssetCriticality Criticality,
    bool IsGateway,
    double? RiskScore,
    RiskLevel? RiskLevel,
    IReadOnlyList<RiskFactor> RiskFactors,
    IReadOnlyList<AuditService> Services,
    IReadOnlyList<AuditVulnerability> Vulnerabilities,
    IReadOnlyList<AuditFinding> Findings);

public sealed record AuditService(
    int Port,
    TransportProtocol Protocol,
    string? Name,
    string? Product,
    string? Version,
    int Confidence,
    bool IsTls,
    AuditCertificate? Certificate);

public sealed record AuditCertificate(string Subject, string Issuer, DateTime NotAfter, bool IsSelfSigned, bool? HostnameMatches, string? TlsProtocol);

/// <param name="Status">State of the match at audit time (open, accepted by the user, resolved).</param>
public sealed record AuditVulnerability(
    string CveId,
    string? Title,
    double? CvssScore,
    RiskLevel? Severity,
    double? EpssScore,
    bool IsKnownExploited,
    VulnerabilityMatchStatus MatchStatus,
    int MatchConfidence,
    string? MatchReason,
    int? Port,
    string? Product,
    string? Version,
    FindingStatus Status);

/// <summary>A configuration finding (e.g. FTP without encryption) – a weakness that is not a CVE.</summary>
public sealed record AuditFinding(
    string RuleId,
    string Title,
    RiskLevel Level,
    double Score,
    int? Port,
    string? Evidence,
    string? Recommendation,
    FindingStatus Status);

/// <param name="Priority">Issue score with the device's context (role, exposure, criticality) – the order to fix things in.</param>
public sealed record AuditRecommendation(
    string Device,
    string? Ip,
    string Title,
    double Priority,
    RiskLevel Level,
    int? Port,
    string Recommendation,
    IReadOnlyList<string> CveIds,
    int KnownExploited);

/// <summary>Changes since the previous audit of the same network (null for the first audit of a network).</summary>
public sealed record AuditChanges(int PreviousScanId, DateTime PreviousAt, double? PostureBefore, double? PostureAfter, IReadOnlyList<AuditChange> Items);

/// <param name="Device">"Raspberry Pi (192.168.0.103)".</param>
public sealed record AuditChange(AuditChangeKind Kind, string Device, string Description);

public enum AuditChangeKind
{
    NewDevice,
    ReturnedDevice,
    MissingDevice,
    PortOpened,
    PortClosed,
    ServiceChanged,
    VersionChanged,
    CertificateChanged,
    OtherChange,
    NewVulnerability,
    ResolvedVulnerability,
    RiskChanged
}

public sealed record AuditAiSummaryInfo(string Text, string? Model, string Language, DateTime CreatedAt);

/// <summary>JSON settings of the export format: readable enums and property names, stable across versions.</summary>
public static class AuditJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        // Imported files are untrusted: deep nesting is refused instead of exhausting the stack.
        MaxDepth = 16
    };
}
