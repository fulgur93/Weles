using System.Globalization;
using System.Text.Json;

namespace Weles.Core.Vulnerabilities;

/// <summary>
/// Converts NVD CVE API 2.0 items ("vulnerabilities[].cve") into <see cref="VulnerabilityRecord"/>.
/// Only CPE configurations analysed by NVD become affected products – they name vendor, product and version ranges
/// precisely enough to match against what a scan detected.
/// </summary>
public static class NvdCveParser
{
    public const int MaxReferences = 12;
    public const int MaxDescriptionLength = 4000;

    /// <summary>Parses one "cve" object. Returns null for rejected CVEs and malformed items.</summary>
    public static VulnerabilityRecord? Parse(JsonElement cve)
    {
        if (cve.ValueKind != JsonValueKind.Object || !cve.TryGetProperty("id", out var idElement) || idElement.GetString() is not { } id) return null;
        if (Str(cve, "vulnStatus") is "Rejected") return null;

        var (score, vector, version, severity) = Cvss(cve);
        return new VulnerabilityRecord
        {
            CveId = id.ToUpperInvariant(),
            Description = Truncate(Description(cve), MaxDescriptionLength),
            CvssScore = score,
            CvssVector = vector,
            CvssVersion = version,
            Severity = severity,
            PublishedAt = Date(Str(cve, "published")),
            LastModifiedAt = Date(Str(cve, "lastModified")),
            References = References(cve),
            Weaknesses = Weaknesses(cve),
            AffectedProducts = Affected(cve),
            Source = "nvd"
        };
    }

    /// <summary>Parses a whole API page: {"totalResults":…,"vulnerabilities":[{"cve":{…}}]}.</summary>
    public static IEnumerable<VulnerabilityRecord> ParsePage(JsonElement page)
    {
        if (!page.TryGetProperty("vulnerabilities", out var items) || items.ValueKind != JsonValueKind.Array) yield break;
        foreach (var item in items.EnumerateArray())
        {
            if (item.TryGetProperty("cve", out var cve) && Parse(cve) is { } record) yield return record;
        }
    }

    private static string? Description(JsonElement cve)
    {
        if (!cve.TryGetProperty("descriptions", out var list) || list.ValueKind != JsonValueKind.Array) return null;
        string? fallback = null;
        foreach (var d in list.EnumerateArray())
        {
            var value = Str(d, "value");
            if (Str(d, "lang") == "en") return value;
            fallback ??= value;
        }

        return fallback;
    }

    /// <summary>CVSS preference: v3.1, v4.0, v3.0, v2 – NVD's own ("Primary") score before a CNA's.</summary>
    private static (double? Score, string? Vector, string? Version, string? Severity) Cvss(JsonElement cve)
    {
        if (!cve.TryGetProperty("metrics", out var metrics) || metrics.ValueKind != JsonValueKind.Object) return default;
        foreach (var key in (string[])["cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"])
        {
            if (!metrics.TryGetProperty(key, out var list) || list.ValueKind != JsonValueKind.Array || list.GetArrayLength() == 0) continue;
            var chosen = list.EnumerateArray().OrderBy(m => Str(m, "type") == "Primary" ? 0 : 1).First();
            if (!chosen.TryGetProperty("cvssData", out var data)) continue;
            double? score = data.TryGetProperty("baseScore", out var s) && s.TryGetDouble(out var v) ? v : null;
            var severity = Str(data, "baseSeverity") ?? Str(chosen, "baseSeverity");
            return (score, Str(data, "vectorString"), Str(data, "version"), severity?.ToUpperInvariant());
        }

        return default;
    }

    private static List<string> References(JsonElement cve)
    {
        var urls = new List<string>();
        if (!cve.TryGetProperty("references", out var list) || list.ValueKind != JsonValueKind.Array) return urls;
        foreach (var r in list.EnumerateArray())
        {
            if (Str(r, "url") is { } url && Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme is "https" or "http" && !urls.Contains(url))
            {
                urls.Add(url);
                if (urls.Count == MaxReferences) break;
            }
        }

        return urls;
    }

    private static List<string> Weaknesses(JsonElement cve)
    {
        var cwes = new List<string>();
        if (!cve.TryGetProperty("weaknesses", out var list) || list.ValueKind != JsonValueKind.Array) return cwes;
        foreach (var w in list.EnumerateArray())
        {
            if (!w.TryGetProperty("description", out var ds) || ds.ValueKind != JsonValueKind.Array) continue;
            foreach (var d in ds.EnumerateArray())
            {
                if (Str(d, "value") is { } value && value.StartsWith("CWE-", StringComparison.Ordinal) && !cwes.Contains(value)) cwes.Add(value);
            }
        }

        return cwes;
    }

    private static List<AffectedProductRecord> Affected(JsonElement cve)
    {
        var result = new List<AffectedProductRecord>();
        if (!cve.TryGetProperty("configurations", out var configurations) || configurations.ValueKind != JsonValueKind.Array) return result;

        foreach (var configuration in configurations.EnumerateArray())
        {
            if (!configuration.TryGetProperty("nodes", out var nodes) || nodes.ValueKind != JsonValueKind.Array) continue;
            var isAnd = Str(configuration, "operator") == "AND";

            var nodeMatches = new List<List<(bool Vulnerable, CpeName Cpe, JsonElement Match)>>();
            var negated = false;
            foreach (var node in nodes.EnumerateArray())
            {
                if (node.TryGetProperty("negate", out var neg) && neg.ValueKind == JsonValueKind.True) negated = true;
                var matches = new List<(bool, CpeName, JsonElement)>();
                if (node.TryGetProperty("cpeMatch", out var cpeMatches) && cpeMatches.ValueKind == JsonValueKind.Array)
                {
                    foreach (var m in cpeMatches.EnumerateArray())
                    {
                        if (CpeName.Parse(Str(m, "criteria")) is { } cpe)
                        {
                            matches.Add((m.TryGetProperty("vulnerable", out var vul) && vul.ValueKind == JsonValueKind.True, cpe, m));
                        }
                    }
                }

                nodeMatches.Add(matches);
            }

            // "NOT running on X" cannot be judged from a network scan – skip rather than guess.
            if (negated) continue;

            for (var i = 0; i < nodeMatches.Count; i++)
            {
                string? condition = null;
                if (isAnd && nodeMatches.Count > 1)
                {
                    var others = nodeMatches.Where((_, j) => j != i).SelectMany(n => n).Select(n => $"{n.Cpe.Vendor}:{n.Cpe.Product}").Distinct().Take(3).ToList();
                    condition = others.Count == 0 ? null : string.Join(", ", others);
                }

                foreach (var (vulnerable, cpe, m) in nodeMatches[i])
                {
                    if (!vulnerable) continue;
                    var record = new AffectedProductRecord(
                        cpe.Part, cpe.Vendor, cpe.Product,
                        Version: cpe.FullVersion,
                        VersionStartIncluding: Str(m, "versionStartIncluding"),
                        VersionStartExcluding: Str(m, "versionStartExcluding"),
                        VersionEndIncluding: Str(m, "versionEndIncluding"),
                        VersionEndExcluding: Str(m, "versionEndExcluding"),
                        Condition: condition);
                    if (record.HasRange) record = record with { Version = null };
                    if (cpe.Version == CpeName.NotApplicable && cpe.Part != "h") continue; // "-" for software: no version applies
                    if (!result.Contains(record)) result.Add(record);
                }
            }
        }

        return result;
    }

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static DateTime? Date(string? value) =>
        DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : null;

    private static string? Truncate(string? value, int max) => value is null || value.Length <= max ? value : value[..max];
}
