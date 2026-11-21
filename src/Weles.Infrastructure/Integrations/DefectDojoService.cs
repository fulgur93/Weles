using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Weles.Core.Enums;
using Weles.Core.Fingerprint;
using Weles.Core.Integrations;
using Weles.Core.Networking;
using Weles.Core.Risk;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Queries;
using Weles.Infrastructure.Settings;

namespace Weles.Infrastructure.Integrations;

/// <summary>Encrypts secrets at rest (API keys). Implemented in the application with ASP.NET Core Data Protection.</summary>
public interface ISecretProtector
{
    string Protect(string plaintext);
    string? Unprotect(string protectedText);
}

public sealed record DojoPreview(int Findings, IReadOnlyDictionary<string, int> BySeverity, IReadOnlyDictionary<string, int> ByKind, int Endpoints);

/// <param name="TestId">DefectDojo test that received the findings (re-imports update it).</param>
public sealed record DojoSendResult(bool Success, string Message, int Sent, int? TestId = null, int? EngagementId = null, int? ProductId = null, DateTime? At = null);

public sealed record DojoSettings(DojoConnection? Connection, bool HasApiKey, DojoExportOptions Options, DojoSendResult? LastResult);

/// <summary>
/// DefectDojo integration: WELES results as findings in DefectDojo's "Generic Findings Import" format – CVE matches (with
/// CVE, CWE, CVSS, EPSS), configuration findings (with CWE), technologies/panels/test environments recognised by signatures
/// and, optionally, every open service. The user decides the granularity. Sending uses <c>reimport-scan</c> with a fixed
/// test title, so each run updates the same DefectDojo test and closes findings WELES no longer sees. Data leaves the
/// computer only to the DefectDojo address the user configured; the API key is stored encrypted and never logged.
/// </summary>
public sealed class DefectDojoService(
    IDbContextFactory<WelesDbContext> contextFactory,
    SettingsService settings,
    NetworkQueries networks,
    WebQueries web,
    ISecretProtector protector,
    TimeProvider time,
    ILogger<DefectDojoService> logger,
    Func<bool, HttpMessageHandler>? handlerFactory = null)
{
    public const string ScanType = "Generic Findings Import";
    private const string ConnectionKey = "dojo.connection";
    private const string OptionsKey = "dojo.options";
    private const string ApiKeyKey = "dojo.apiKey";
    private const string LastResultKey = "dojo.lastResult";

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    // ------------------------------------------------------------------ settings

    public async Task<DojoSettings> SettingsAsync(CancellationToken ct = default) => new(
        Read<DojoConnection>(await settings.GetAsync(ConnectionKey, ct)),
        await settings.GetAsync(ApiKeyKey, ct) is { Length: > 0 },
        Read<DojoExportOptions>(await settings.GetAsync(OptionsKey, ct)) ?? new DojoExportOptions(),
        Read<DojoSendResult>(await settings.GetAsync(LastResultKey, ct)));

    /// <param name="apiKey">New key; null keeps the stored one, "" removes it.</param>
    public async Task<IReadOnlyList<string>> SaveAsync(DojoConnection connection, string? apiKey, DojoExportOptions options, CancellationToken ct = default)
    {
        var errors = ValidateUrl(connection.Url).ToList();
        foreach (var (value, name) in new[] { (connection.ProductType, "typ produktu"), (connection.Product, "produkt"), (connection.Engagement, "engagement"), (connection.TestTitle, "tytuł testu") })
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length > 200) errors.Add($"Podaj {name} (1–200 znaków).");
        }

        if (apiKey is { Length: > 200 }) errors.Add("Klucz API jest za długi.");
        if (!DojoSeverity.All.Contains(options.MinimumSeverity)) errors.Add("Nieznany minimalny poziom.");
        if (errors.Count > 0) return errors;

        await settings.SetAsync(ConnectionKey, JsonSerializer.Serialize(connection with { Url = connection.Url.Trim().TrimEnd('/') }, Json), ct);
        await settings.SetAsync(OptionsKey, JsonSerializer.Serialize(options, Json), ct);
        if (apiKey is not null) await settings.SetAsync(ApiKeyKey, apiKey.Length == 0 ? null : protector.Protect(apiKey.Trim()), ct);
        logger.LogInformation("DefectDojo settings saved ({Url}, key {KeyState})", connection.Url, apiKey is null ? "unchanged" : apiKey.Length == 0 ? "removed" : "replaced");
        return [];
    }

    /// <summary>https:// – or http:// only for this computer and private networks (a lab instance).</summary>
    public static IEnumerable<string> ValidateUrl(string? url)
    {
        if (!Uri.TryCreate(url?.Trim(), UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || !string.IsNullOrEmpty(uri.UserInfo))
        {
            yield return "Adres DefectDojo musi mieć postać https://serwer (bez loginu i hasła w adresie).";
            yield break;
        }

        if (uri.Scheme == "http" && !(uri.IsLoopback || IPAddress.TryParse(uri.Host, out var ip) && !AddressClassifier.IsPublic(ip) || uri.Host.EndsWith(".local", StringComparison.OrdinalIgnoreCase)))
            yield return "Niezaszyfrowane http:// jest dozwolone tylko dla tego komputera i adresów prywatnych – klucz API przechodzi w nagłówku.";
    }

    // ------------------------------------------------------------------ findings

    public async Task<DojoReport> BuildAsync(DojoExportOptions options, CancellationToken ct = default)
    {
        var context = await networks.ContextAsync(ct);
        var filter = context.Normalize(options.Network);
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        HashSet<int>? scanAssets = null;
        if (options.ScanId is { } scanId)
        {
            scanAssets = (await db.DiscoveredHosts.AsNoTracking().Where(h => h.ScanId == scanId && h.AssetId != null).Select(h => h.AssetId!.Value).ToListAsync(ct)).ToHashSet();
        }

        bool Include(int assetId) => context.IncludesAsset(filter, assetId) && (scanAssets is null || scanAssets.Contains(assetId));
        var assets = (await db.Assets.AsNoTracking().Select(a => new { a.Id, Name = a.CustomName ?? a.DisplayName, a.PrimaryIpAddress, a.MacAddress, a.Vendor, a.AssetType, a.UserAssetType, a.Criticality }).ToListAsync(ct))
            .Where(a => Include(a.Id) && a.PrimaryIpAddress is not null).ToDictionary(a => a.Id);
        var ids = assets.Keys.ToList();
        var items = new List<Item>();
        string Today(DateTime? d) => (d ?? time.GetUtcNow().UtcDateTime).ToString("yyyy-MM-dd");
        string Device(int id) => $"{assets[id].Name} ({assets[id].PrimaryIpAddress}{(assets[id].MacAddress is { } mac ? ", MAC " + mac : "")})";

        if (options.IncludeCves)
        {
            var statuses = options.IncludeAccepted ? new[] { FindingStatus.Open, FindingStatus.Accepted } : [FindingStatus.Open];
            var rows = await db.AssetVulnerabilities.AsNoTracking()
                .Where(v => ids.Contains(v.AssetId) && statuses.Contains(v.Status) && v.MatchStatus <= options.MinimumMatch)
                .Select(v => new
                {
                    v.AssetId, v.Port, v.Product, v.DetectedVersion, v.MatchStatus, v.MatchConfidence, v.MatchReason, v.Status, v.FirstDetectedAt, v.LastDetectedAt,
                    v.Vulnerability!.CveId, v.Vulnerability.Title, v.Vulnerability.Description, v.Vulnerability.CvssScore, v.Vulnerability.CvssVector, v.Vulnerability.Severity,
                    v.Vulnerability.EpssScore, v.Vulnerability.EpssPercentile, v.Vulnerability.IsKnownExploited, v.Vulnerability.KevDateAdded, v.Vulnerability.Weaknesses
                })
                .ToListAsync(ct);
            foreach (var v in rows)
            {
                var cwe = v.Weaknesses?.Split(',').Select(w => int.TryParse(w.Trim().Replace("CWE-", ""), out var n) ? n : (int?)null).FirstOrDefault(n => n is not null);
                var what = $"{v.Product} {v.DetectedVersion}".Trim();
                items.Add(new Item(
                    Kind: "cve", IssueKey: $"cve:{v.CveId}:{v.Product}:{v.DetectedVersion}", AssetId: v.AssetId, Port: v.Port, Protocol: null,
                    Title: $"{v.CveId} – {(what.Length > 0 ? what : v.Title ?? "podatność")}",
                    Severity: v.CvssScore is null && v.Severity is { } sev ? DojoSeverity.FromRisk(sev) : DojoSeverity.FromCvss(v.CvssScore),
                    Description: $"""
                        **Urządzenie:** {Device(v.AssetId)}{(v.Port is { } p ? $", port {p}" : "")}
                        **Oprogramowanie:** {(what.Length > 0 ? what : "—")}
                        **Dopasowanie:** {v.MatchStatus} ({v.MatchConfidence}%) – {v.MatchReason}
                        **CVSS:** {v.CvssScore?.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) ?? "—"} {v.CvssVector} · **EPSS:** {(v.EpssScore is { } e ? (e * 100).ToString("0.##", System.Globalization.CultureInfo.InvariantCulture) + "%" : "—")} · **CISA KEV:** {(v.IsKnownExploited ? $"tak (od {v.KevDateAdded:yyyy-MM-dd})" : "nie")}
                        **CWE:** {v.Weaknesses ?? "—"}
                        **Wykryto:** {v.FirstDetectedAt:yyyy-MM-dd} · **ostatnio:** {v.LastDetectedAt:yyyy-MM-dd}{(v.Status == FindingStatus.Accepted ? "\n**Ryzyko zaakceptowane w WELES.**" : "")}

                        {Cut(v.Description, 2000)}
                        """,
                    Mitigation: "Zaktualizuj oprogramowanie do wersji bez tej podatności; dla pakietów dystrybucji zainstaluj aktualizacje bezpieczeństwa (poprawki bywają przenoszone bez zmiany numeru wersji).",
                    Impact: v.IsKnownExploited ? "Podatność w katalogu CISA KEV – znane wykorzystanie w atakach." : null,
                    References: $"https://nvd.nist.gov/vuln/detail/{v.CveId}" + (cwe is { } c ? $"\nhttps://cwe.mitre.org/data/definitions/{c}.html" : ""),
                    Date: Today(v.LastDetectedAt), Cwe: cwe, Cve: v.CveId, CvssVector: v.CvssVector?.StartsWith("CVSS:3", StringComparison.Ordinal) == true ? v.CvssVector : null,
                    CvssScore: v.CvssScore, Epss: v.EpssScore, EpssPercentile: v.EpssPercentile, Component: v.Product, Version: v.DetectedVersion, VulnId: v.CveId,
                    Active: v.Status == FindingStatus.Open, Verified: v.MatchStatus == VulnerabilityMatchStatus.Confirmed));
            }
        }

        if (options.IncludeConfiguration)
        {
            var statuses = options.IncludeAccepted ? new[] { FindingStatus.Open, FindingStatus.Accepted } : [FindingStatus.Open];
            var rows = await db.RiskFindings.AsNoTracking().Where(f => ids.Contains(f.AssetId) && statuses.Contains(f.Status)).ToListAsync(ct);
            foreach (var f in rows)
            {
                var cwe = RiskRules.CweOf(f.RuleId);
                items.Add(new Item("configuration", $"rule:{f.RuleId}", f.AssetId, f.Port, null, f.Title, DojoSeverity.FromRisk(f.Level),
                    $"""
                    **Urządzenie:** {Device(f.AssetId)}{(f.Port is { } p ? $", port {p}" : "")}
                    **Reguła WELES:** {f.RuleId} · **kategoria:** {f.Category} · **pewność:** {f.Confidence}%
                    **Dowód ze skanu:** {f.Evidence}
                    **CWE:** {(cwe is { } c ? "CWE-" + c : "—")} · **MITRE ATT&CK:** {f.AttackTechniques ?? "—"}
                    **Wykryto:** {f.CreatedAt:yyyy-MM-dd} · **ostatnio:** {f.LastDetectedAt:yyyy-MM-dd}{(f.Status == FindingStatus.Accepted ? "\n**Ryzyko zaakceptowane w WELES.**" : "")}

                    {f.Description}
                    """,
                    f.Recommendation, null, cwe is { } c2 ? $"https://cwe.mitre.org/data/definitions/{c2}.html" : null, Today(f.LastDetectedAt), cwe, null, null, null, null, null,
                    null, null, f.RuleId, f.Status == FindingStatus.Open, f.Confidence >= 80));
            }
        }

        if (options.IncludeWeb)
        {
            foreach (var row in await web.LatestAsync(Include, options.ScanId, ct))
            {
                if (row.AssetId is not { } assetId || !assets.ContainsKey(assetId)) continue;
                foreach (var t in row.Technologies)
                {
                    var severity = t.SignatureId == "debug-mode" ? DojoSeverity.Medium
                        : t.Category is SignatureCategory.AdminPanel or SignatureCategory.Staging || t.SignatureId == "directory-listing" ? DojoSeverity.Low
                        : DojoSeverity.Info;
                    var label = t.Category switch
                    {
                        SignatureCategory.AdminPanel => "Panel administracyjny",
                        SignatureCategory.Staging => "Środowisko testowe",
                        SignatureCategory.Interesting => "Obserwacja",
                        _ => "Technologia"
                    };
                    var cweOfSignature = await TechnologyCweAsync(db, row.ServiceId, t.SignatureId, ct);
                    items.Add(new Item("web", $"web:{t.SignatureId}:{t.Version}", assetId, row.Port, row.Web.Url.StartsWith("https") ? "https" : "http",
                        $"{label}: {t.Name}{(t.Version is null ? "" : " " + t.Version)}", severity,
                        $"""
                        **Urządzenie:** {Device(assetId)} · **adres:** {row.Web.Url}
                        **HTTP:** {row.Web.Status} · **tytuł:** {row.Web.Title ?? "—"} · **Server:** {row.Web.Header("Server") ?? "—"}
                        **Kategoria:** {t.Category} · **pewność:** {t.Confidence}% · **sygnatura:** {t.SignatureId}
                        **Dowody:**
                        {string.Join('\n', (t.Evidence ?? "").Split('\n').Select(e => "- " + e))}
                        **Ocena ciekawości WELES:** {row.Interest}/100 ({string.Join("; ", row.InterestReasons)})
                        """,
                        t.Category == SignatureCategory.AdminPanel ? "Ogranicz dostęp do panelu (VPN, lista adresów, uwierzytelnianie wieloskładnikowe) albo wyłącz go, jeśli nie jest potrzebny." :
                        t.Category == SignatureCategory.Staging ? "Środowisko testowe nie powinno być dostępne z sieci produkcyjnej – ogranicz dostęp lub wyłącz tryb debugowania." : null,
                        null, null, Today(row.ScannedAt), cweOfSignature, null, null, null, null, null, t.Name, t.Version, t.SignatureId, true, false));
                }
            }
        }

        if (options.IncludeServices)
        {
            var hosts = await db.DiscoveredHosts.AsNoTracking().Where(h => h.AssetId != null && ids.Contains(h.AssetId.Value) && h.Scan!.Status == ScanStatus.Completed)
                .Where(h => options.ScanId == null || h.ScanId == options.ScanId)
                .Select(h => new { AssetId = h.AssetId!.Value, h.Id, At = h.Scan!.StartedAt ?? h.Scan.CreatedAt, Ports = h.Ports.Select(p => new { p.Port, p.Protocol, p.Service!.ServiceName, p.Service.Product, p.Service.Version }) })
                .ToListAsync(ct);
            foreach (var h in hosts.GroupBy(h => h.AssetId).Select(g => g.MaxBy(x => x.At)!))
            {
                foreach (var p in h.Ports)
                {
                    var what = $"{p.Product} {p.Version}".Trim();
                    items.Add(new Item("service", $"service:{p.Port}:{p.ServiceName}", h.AssetId, p.Port, p.ServiceName, $"Otwarta usługa {p.ServiceName ?? "?"} (port {p.Port}/{p.Protocol.ToString().ToLowerInvariant()})",
                        DojoSeverity.Info, $"**Urządzenie:** {Device(h.AssetId)}\n**Oprogramowanie:** {(what.Length > 0 ? what : "nierozpoznane")}\n**Obserwacja ze skanu z:** {h.At:yyyy-MM-dd HH:mm} UTC",
                        null, null, null, Today(h.At), null, null, null, null, null, null, p.Product, p.Version, $"service-{p.Port}", true, false));
                }
            }
        }

        items = items.Where(i => DojoSeverity.Rank(i.Severity) >= DojoSeverity.Rank(options.MinimumSeverity)).ToList();
        var findings = options.Grouping == DojoGrouping.PerIssue
            ? items.GroupBy(i => i.IssueKey).Select(g => ToFinding(g.ToList(), assets.ToDictionary(a => a.Key, a => a.Value.PrimaryIpAddress!))).ToList()
            : items.Select(i => ToFinding([i], assets.ToDictionary(a => a.Key, a => a.Value.PrimaryIpAddress!))).ToList();
        return new DojoReport(findings.OrderByDescending(f => DojoSeverity.Rank(f.Severity)).ThenBy(f => f.Title, StringComparer.Ordinal).ToList());
    }

    private static async Task<int?> TechnologyCweAsync(WelesDbContext db, int serviceId, string signatureId, CancellationToken ct) =>
        await db.ServiceTechnologies.AsNoTracking().Where(t => t.DiscoveredServiceId == serviceId && t.SignatureId == signatureId).Select(t => t.Cwe).FirstOrDefaultAsync(ct);

    public static DojoPreview Preview(DojoReport report) => new(report.Findings.Count,
        report.Findings.GroupBy(f => f.Severity).ToDictionary(g => g.Key, g => g.Count()),
        report.Findings.GroupBy(f => f.UniqueId.Split(':')[1]).ToDictionary(g => g.Key, g => g.Count()),
        report.Findings.Sum(f => f.Endpoints.Count));

    private sealed record Item(string Kind, string IssueKey, int AssetId, int? Port, string? Protocol, string Title, string Severity, string Description, string? Mitigation,
        string? Impact, string? References, string Date, int? Cwe, string? Cve, string? CvssVector, double? CvssScore, double? Epss, double? EpssPercentile,
        string? Component, string? Version, string? VulnId, bool Active, bool Verified);

    private static DojoFinding ToFinding(IReadOnlyList<Item> group, IReadOnlyDictionary<int, string> ips)
    {
        var first = group[0];
        var endpoints = group.Select(i => new DojoEndpoint(ips[i.AssetId], i.Port, i.Protocol)).Distinct().ToList();
        // Stable between runs: re-import in DefectDojo updates the finding instead of creating a new one.
        var uniqueId = group.Count == 1 && endpoints.Count == 1
            ? $"weles:{first.Kind}:{first.IssueKey}:{endpoints[0].Host}:{endpoints[0].Port}"
            : $"weles:{first.Kind}:{first.IssueKey}";
        var description = group.Count == 1 ? first.Description
            : $"**Dotyczy {endpoints.Count} punktów:** {string.Join(", ", endpoints.Select(e => e.Port is null ? e.Host : $"{e.Host}:{e.Port}"))}\n\n" + first.Description;
        return new DojoFinding(Cut(first.Title, 500)!, group.Max(i => (DojoSeverity.Rank(i.Severity), i.Severity)).Severity, Cut(description, 30_000)!, first.Mitigation,
            first.Impact, first.References, group.Max(i => i.Date)!, first.Cwe, first.Cve, first.Cve is null ? null : [first.Cve], first.CvssVector, first.CvssScore,
            first.Epss, first.EpssPercentile, first.Component, first.Version, first.Protocol, uniqueId, first.VulnId, group.Any(i => i.Active), group.All(i => i.Verified),
            false, true, endpoints);
    }

    public static string Serialize(DojoReport report) => JsonSerializer.Serialize(report, Json);

    // ------------------------------------------------------------------ API

    public async Task<DojoSendResult> TestConnectionAsync(CancellationToken ct = default)
    {
        var (connection, key, error) = await ConnectionAsync(ct);
        if (error is not null) return new DojoSendResult(false, error, 0);
        try
        {
            using var client = Client(connection!, key!);
            using var response = await client.GetAsync("api/v2/products/?limit=1", ct);
            return response.StatusCode switch
            {
                HttpStatusCode.OK => new DojoSendResult(true, $"Połączono z DefectDojo ({connection!.Url}) – klucz API działa.", 0),
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => new DojoSendResult(false, "DefectDojo odrzucił klucz API (401/403).", 0),
                _ => new DojoSendResult(false, $"DefectDojo odpowiedział kodem {(int)response.StatusCode} – sprawdź adres.", 0)
            };
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return new DojoSendResult(false, $"Brak połączenia z DefectDojo: {ex.Message}", 0);
        }
    }

    /// <summary>Re-imports the findings into the configured product / engagement / test (created when missing).</summary>
    public async Task<DojoSendResult> SendAsync(DojoExportOptions options, CancellationToken ct = default)
    {
        var (connection, key, error) = await ConnectionAsync(ct);
        if (error is not null) return new DojoSendResult(false, error, 0);
        var report = await BuildAsync(options, ct);
        DojoSendResult result;
        try
        {
            using var client = Client(connection!, key!);
            using var form = new MultipartFormDataContent();
            void Field(string name, string value) => form.Add(new StringContent(value), name);
            Field("scan_type", ScanType);
            Field("product_type_name", connection!.ProductType);
            Field("product_name", connection.Product);
            Field("engagement_name", connection.Engagement);
            Field("test_title", connection.TestTitle);
            Field("auto_create_context", "true");
            Field("close_old_findings", connection.CloseOldFindings ? "true" : "false");
            Field("minimum_severity", options.MinimumSeverity);
            Field("scan_date", time.GetUtcNow().UtcDateTime.ToString("yyyy-MM-dd"));
            Field("active", "true");
            Field("verified", "false");
            Field("tags", "weles");
            var file = new ByteArrayContent(Encoding.UTF8.GetBytes(Serialize(report)));
            file.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            form.Add(file, "file", "weles-findings.json");
            using var response = await client.PostAsync("api/v2/reimport-scan/", form, ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            if (response.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(body.Length == 0 ? "{}" : body);
                int? Id(params string[] names) => names.Select(n => doc.RootElement.TryGetProperty(n, out var v) && v.TryGetInt32(out var i) ? i : (int?)null).FirstOrDefault(i => i is not null);
                result = new DojoSendResult(true, $"Wysłano {report.Findings.Count} znalezisk do DefectDojo.", report.Findings.Count,
                    Id("test", "test_id"), Id("engagement", "engagement_id"), Id("product", "product_id"), time.GetUtcNow().UtcDateTime);
            }
            else
            {
                result = new DojoSendResult(false, $"DefectDojo odrzucił import (HTTP {(int)response.StatusCode}): {Cut(body, 400)}", 0, At: time.GetUtcNow().UtcDateTime);
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            result = new DojoSendResult(false, $"Wysyłanie do DefectDojo nie powiodło się: {ex.Message}", 0, At: time.GetUtcNow().UtcDateTime);
        }

        await settings.SetAsync(LastResultKey, JsonSerializer.Serialize(result, Json), ct);
        logger.LogInformation("DefectDojo export: {Success}, {Count} findings ({Url})", result.Success, result.Sent, connection!.Url);
        return result;
    }

    private async Task<(DojoConnection? Connection, string? Key, string? Error)> ConnectionAsync(CancellationToken ct)
    {
        var connection = Read<DojoConnection>(await settings.GetAsync(ConnectionKey, ct));
        if (connection is null) return (null, null, "Najpierw zapisz adres DefectDojo.");
        if (ValidateUrl(connection.Url).FirstOrDefault() is { } invalid) return (null, null, invalid);
        var stored = await settings.GetAsync(ApiKeyKey, ct);
        var key = stored is null ? null : protector.Unprotect(stored);
        return key is null ? (null, null, "Brak klucza API DefectDojo (lub nie da się go odszyfrować – wpisz go ponownie).") : (connection, key, null);
    }

    private HttpClient Client(DojoConnection connection, string key)
    {
        var handler = handlerFactory?.Invoke(connection.VerifyTls) ?? new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(10),
            SslOptions = connection.VerifyTls ? new() : new() { RemoteCertificateValidationCallback = (_, _, _, _) => true }
        };
        var client = new HttpClient(handler) { BaseAddress = new Uri(connection.Url.TrimEnd('/') + "/"), Timeout = TimeSpan.FromMinutes(5) };
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Token", key);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("WELES-defectdojo/1.0");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        return client;
    }

    private static T? Read<T>(string? json) where T : class
    {
        if (string.IsNullOrEmpty(json)) return null;
        try
        {
            return JsonSerializer.Deserialize<T>(json, Json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? Cut(string? value, int max) => value is null || value.Length <= max ? value : value[..max];
}
