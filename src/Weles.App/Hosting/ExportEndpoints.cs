using System.Text;
using System.Text.Json;
using Weles.Core.Fingerprint;
using Weles.Infrastructure.Fingerprint;
using Weles.Infrastructure.Queries;

namespace Weles.App.Hosting;

/// <summary>
/// Result exports for other tools (spreadsheets, scripts, DefectDojo, SIEM): CSV and JSON, generated on request from the
/// database. Behind <see cref="LocalAccessGuardMiddleware"/> like every endpoint. CSV cells that a spreadsheet would run as
/// a formula are neutralised (CSV injection).
/// </summary>
public static class ExportEndpoints
{
    public static readonly JsonSerializerOptions Json = new(SignatureEngine.Json) { WriteIndented = true };

    public static void MapExportEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/export/web.{format}", async (string format, WebQueries web, CancellationToken ct) =>
        {
            var rows = await web.LatestAsync(ct: ct);
            if (format == "json")
            {
                var items = rows.Select(r => new
                {
                    r.Ip, r.Port, r.AssetName, r.Web.Url, r.Web.Status, r.Web.Title, r.ScanId, r.ScannedAt, r.Interest, r.InterestReasons,
                    Technologies = r.Technologies.Select(t => new { t.Name, t.Category, t.Version, t.Confidence, t.SignatureId, t.Evidence }),
                    r.Web.Headers, Cookies = r.Web.Cookies, r.Web.Redirects, r.Web.FaviconMmh3, r.Web.FaviconMd5,
                    Paths = r.Web.Paths.Select(p => new { p.Path, p.Status, p.Title })
                });
                return Results.Text(JsonSerializer.Serialize(items, Json), "application/json", Encoding.UTF8);
            }

            if (format != "csv") return Results.NotFound();
            var csv = Csv(["ip", "port", "url", "status", "title", "server", "technologies", "admin_panel", "staging", "interest", "cookies", "interesting_headers", "redirects", "favicon_mmh3", "scan_id", "scanned_at"],
                rows.Select(r => new[]
                {
                    r.Ip, r.Port.ToString(), r.Web.Url, r.Web.Status.ToString(), r.Web.Title ?? "", r.Web.Header("Server") ?? "",
                    string.Join("; ", r.Technologies.Select(t => t.Name + (t.Version is null ? "" : " " + t.Version))),
                    r.Technologies.Any(t => t.Category == SignatureCategory.AdminPanel) ? "yes" : "no",
                    r.Technologies.Any(t => t.Category == SignatureCategory.Staging) ? "yes" : "no",
                    r.Interest.ToString(), string.Join("; ", r.Web.Cookies.Select(c => c.Name)), string.Join("; ", r.InterestingHeaders),
                    string.Join("; ", r.Web.Redirects), r.Web.FaviconMmh3?.ToString() ?? "", r.ScanId.ToString(), r.ScannedAt.ToString("O")
                }));
            return Results.File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(csv)).ToArray(), "text/csv", "weles-web.csv");
        });

        // Scan results in the format the import accepts (round trip): one scan, or the latest observation of every device.
        app.MapGet("/api/export/scans/{id:int}.{format}", async (int id, string format, Microsoft.EntityFrameworkCore.IDbContextFactory<Weles.Infrastructure.Database.WelesDbContext> factory, CancellationToken ct) =>
            await ResultsAsync(factory, format, id, ct));
        app.MapGet("/api/export/results.{format}", async (string format, Microsoft.EntityFrameworkCore.IDbContextFactory<Weles.Infrastructure.Database.WelesDbContext> factory, CancellationToken ct) =>
            await ResultsAsync(factory, format, null, ct));

        // DefectDojo "Generic Findings Import" file with the saved granularity – for a manual upload.
        app.MapGet("/api/export/defectdojo.json", async (Weles.Infrastructure.Integrations.DefectDojoService dojo, CancellationToken ct) =>
        {
            var options = (await dojo.SettingsAsync(ct)).Options;
            var report = await dojo.BuildAsync(options, ct);
            return Results.File(Encoding.UTF8.GetBytes(Weles.Infrastructure.Integrations.DefectDojoService.Serialize(report)), "application/json", "weles-defectdojo.json");
        });

        app.MapGet("/api/export/signatures.json", async (SignatureService signatures, CancellationToken ct) =>
            Results.File(Encoding.UTF8.GetBytes(await signatures.ExportAsync(ct)), "application/json", "weles-signatures.json"));
    }

    private sealed record ResultRow(int ScanId, DateTime At, int? AssetId, string Ip, string? Hostname, string? Mac, string? Vendor, int? Port, string? Protocol,
        string? Service, string? Product, string? Version, string? Cpe, string? Banner);

    private static async Task<IResult> ResultsAsync(Microsoft.EntityFrameworkCore.IDbContextFactory<Weles.Infrastructure.Database.WelesDbContext> factory, string format, int? scanId, CancellationToken ct)
    {
        if (format is not ("csv" or "json")) return Results.NotFound();
        await using var db = await factory.CreateDbContextAsync(ct);
        var hosts = db.DiscoveredHosts.Where(h => h.Scan!.Status == Weles.Core.Enums.ScanStatus.Completed);
        if (scanId is { } id) hosts = hosts.Where(h => h.ScanId == id);
        var rows = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.ToListAsync(hosts.Select(h => new
        {
            h.ScanId, At = h.Scan!.StartedAt ?? h.Scan.CreatedAt, h.AssetId, h.IpAddress, h.Hostname, h.MacAddress, h.Vendor,
            Ports = h.Ports.Select(p => new { p.Port, p.Protocol, p.Service!.ServiceName, p.Service.Product, p.Service.Version, p.Service.Cpe, p.Service.Banner })
        }), ct);
        if (scanId is null) rows = rows.GroupBy(r => r.AssetId?.ToString() ?? "ip:" + r.IpAddress).Select(g => g.MaxBy(r => r.At)!).ToList();
        if (scanId is not null && rows.Count == 0 && !await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.AnyAsync(db.Scans, s => s.Id == scanId, ct)) return Results.NotFound();
        var name = scanId is { } n ? $"weles-scan-{n}" : "weles-results";
        if (format == "json")
        {
            var doc = new
            {
                Format = "weles-scan-results", Version = 1, ScanId = scanId, ExportedAt = DateTime.UtcNow,
                Hosts = rows.OrderBy(r => r.IpAddress, StringComparer.Ordinal).Select(r => new
                {
                    Ip = r.IpAddress, r.Hostname, Mac = r.MacAddress, r.Vendor, r.ScanId, ScannedAt = r.At,
                    Ports = r.Ports.OrderBy(p => p.Port).Select(p => new { p.Port, Protocol = p.Protocol.ToString().ToLowerInvariant(), Service = p.ServiceName, p.Product, p.Version, p.Cpe, p.Banner })
                })
            };
            return Results.File(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(doc, Json)), "application/json", name + ".json");
        }

        var csv = Csv(["ip", "hostname", "mac", "vendor", "port", "protocol", "service", "product", "version", "cpe", "banner", "scan_id", "scanned_at"],
            rows.OrderBy(r => r.IpAddress, StringComparer.Ordinal).SelectMany(r => (r.Ports.Any() ? r.Ports.OrderBy(p => p.Port).Select(p => (Port: (int?)p.Port, p.Protocol, p.ServiceName, p.Product, p.Version, p.Cpe, p.Banner))
                    : [(null, Weles.Core.Enums.TransportProtocol.Tcp, null, null, null, null, null)])
                .Select(p => new[]
                {
                    r.IpAddress, r.Hostname ?? "", r.MacAddress ?? "", r.Vendor ?? "", p.Port?.ToString() ?? "", p.Port is null ? "" : p.Protocol.ToString().ToLowerInvariant(),
                    p.ServiceName ?? "", p.Product ?? "", p.Version ?? "", p.Cpe ?? "", (p.Banner ?? "").Replace('\n', ' '), r.ScanId.ToString(), r.At.ToString("O")
                })));
        return Results.File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(csv)).ToArray(), "text/csv", name + ".csv");
    }

    /// <summary>RFC 4180 CSV; a cell starting with = + - @ (or tab/CR) gets a leading apostrophe so spreadsheets do not evaluate it.</summary>
    public static string Csv(IReadOnlyList<string> header, IEnumerable<IReadOnlyList<string>> rows)
    {
        var sb = new StringBuilder();
        void Line(IEnumerable<string> cells) => sb.Append(string.Join(',', cells.Select(Cell))).Append("\r\n");
        Line(header);
        foreach (var row in rows) Line(row);
        return sb.ToString();
    }

    private static string Cell(string value)
    {
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r') value = "'" + value;
        return value.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }
}
