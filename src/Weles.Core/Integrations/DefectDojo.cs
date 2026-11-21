using System.Text.Json.Serialization;
using Weles.Core.Enums;

namespace Weles.Core.Integrations;

/// <summary>What is sent to DefectDojo – chosen by the user (granularity).</summary>
public enum DojoGrouping
{
    /// <summary>One finding per issue per host and port (precise status tracking per endpoint).</summary>
    PerEndpoint = 0,
    /// <summary>One finding per issue (CVE, rule, technology) with every affected host:port as its endpoints.</summary>
    PerIssue = 1
}

/// <param name="IncludeCves">CVE matches from the vulnerability database.</param>
/// <param name="MinimumMatch">Weakest CVE match certainty sent (Confirmed &lt; Probable &lt; NeedsVerification &lt; InsufficientData).</param>
/// <param name="IncludeConfiguration">Configuration findings (e.g. FTP without encryption) with their CWE.</param>
/// <param name="IncludeWeb">Technologies, admin panels and test environments recognised by signatures (Info/Low).</param>
/// <param name="IncludeServices">Every open service as an informational finding (inventory).</param>
/// <param name="IncludeAccepted">Risks the user accepted in WELES (sent as inactive).</param>
/// <param name="Network">Network filter key (all, current, gw:…, ext:…) – the same choice as on the analysis pages.</param>
/// <param name="ScanId">Only what one scan saw; null – the latest state of every device.</param>
public sealed record DojoExportOptions(
    bool IncludeCves = true,
    VulnerabilityMatchStatus MinimumMatch = VulnerabilityMatchStatus.NeedsVerification,
    bool IncludeConfiguration = true,
    bool IncludeWeb = true,
    bool IncludeServices = false,
    bool IncludeAccepted = false,
    string MinimumSeverity = DojoSeverity.Info,
    DojoGrouping Grouping = DojoGrouping.PerEndpoint,
    string Network = "all",
    int? ScanId = null);

/// <summary>DefectDojo connection. The API key is stored separately, encrypted.</summary>
/// <param name="TestTitle">Re-import target: every send updates this test, so DefectDojo closes findings WELES no longer sees.</param>
public sealed record DojoConnection(string Url, string ProductType = "WELES", string Product = "WELES", string Engagement = "Attack Surface", string TestTitle = "WELES discovery",
    bool CloseOldFindings = true, bool VerifyTls = true);

public static class DojoSeverity
{
    public const string Critical = "Critical", High = "High", Medium = "Medium", Low = "Low", Info = "Info";
    public static readonly string[] All = [Info, Low, Medium, High, Critical];

    public static int Rank(string severity) => Array.IndexOf(All, severity) is >= 0 and var i ? i : 0;

    public static string FromRisk(RiskLevel level) => level switch
    {
        RiskLevel.Critical => Critical,
        RiskLevel.High => High,
        RiskLevel.Medium => Medium,
        RiskLevel.Low => Low,
        _ => Info
    };

    /// <summary>CVSS v3 qualitative scale.</summary>
    public static string FromCvss(double? score) => score switch
    {
        >= 9.0 => Critical,
        >= 7.0 => High,
        >= 4.0 => Medium,
        > 0 => Low,
        _ => Info
    };
}

/// <summary>An endpoint of a finding ("host:port/protocol").</summary>
public sealed record DojoEndpoint(
    [property: JsonPropertyName("host")] string Host,
    [property: JsonPropertyName("port")] int? Port,
    [property: JsonPropertyName("protocol")] string? Protocol);

/// <summary>
/// One finding in DefectDojo's "Generic Findings Import" JSON. Only fields of DefectDojo's Finding model are used
/// (unknown fields make the import fail). <see cref="UniqueId"/> is stable between runs, so re-import updates findings.
/// </summary>
public sealed record DojoFinding(
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("mitigation")] string? Mitigation,
    [property: JsonPropertyName("impact")] string? Impact,
    [property: JsonPropertyName("references")] string? References,
    [property: JsonPropertyName("date")] string Date,
    [property: JsonPropertyName("cwe")] int? Cwe,
    [property: JsonPropertyName("cve")] string? Cve,
    [property: JsonPropertyName("vulnerability_ids")] IReadOnlyList<string>? VulnerabilityIds,
    [property: JsonPropertyName("cvssv3")] string? CvssVector,
    [property: JsonPropertyName("cvssv3_score")] double? CvssScore,
    [property: JsonPropertyName("epss_score")] double? EpssScore,
    [property: JsonPropertyName("epss_percentile")] double? EpssPercentile,
    [property: JsonPropertyName("component_name")] string? ComponentName,
    [property: JsonPropertyName("component_version")] string? ComponentVersion,
    [property: JsonPropertyName("service")] string? Service,
    [property: JsonPropertyName("unique_id_from_tool")] string UniqueId,
    [property: JsonPropertyName("vuln_id_from_tool")] string? VulnIdFromTool,
    [property: JsonPropertyName("active")] bool Active,
    [property: JsonPropertyName("verified")] bool Verified,
    [property: JsonPropertyName("static_finding")] bool StaticFinding,
    [property: JsonPropertyName("dynamic_finding")] bool DynamicFinding,
    [property: JsonPropertyName("endpoints")] IReadOnlyList<DojoEndpoint> Endpoints);

public sealed record DojoReport([property: JsonPropertyName("findings")] IReadOnlyList<DojoFinding> Findings);
