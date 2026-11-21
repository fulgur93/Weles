using Microsoft.EntityFrameworkCore;
using Weles.Core.Enums;
using Weles.Core.Fingerprint;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Fingerprint;

namespace Weles.Infrastructure.Queries;

public sealed record TechnologyView(string SignatureId, string Name, SignatureCategory Category, string? Version, int Confidence, string? Evidence);

/// <param name="Interest">0–100 analytical priority ("how interesting"): admin panels, test environments, debug output,
/// disclosed versions and weak cookies first. Each point has a reason in <see cref="InterestReasons"/>.</param>
public sealed record WebServiceRow(
    int ServiceId,
    int ScanId,
    DateTime ScannedAt,
    int? AssetId,
    string AssetName,
    string Ip,
    int Port,
    WebObservation Web,
    IReadOnlyList<TechnologyView> Technologies,
    int Interest,
    IReadOnlyList<string> InterestReasons,
    IReadOnlyList<string> InterestingHeaders,
    IReadOnlyList<string> CookieIssues);

/// <summary>The latest observation of every web service (asset + port) with its technologies – the "Web services" view and exports.</summary>
public sealed class WebQueries(IDbContextFactory<WelesDbContext> contextFactory)
{
    /// <summary>Headers worth a look: they disclose software, versions, internals or debug state.</summary>
    public static readonly string[] InterestingHeaderNames =
    [
        "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Debug-Token", "X-Debug-Token-Link", "X-Runtime",
        "X-Backend-Server", "X-Served-By", "Via", "X-Varnish", "X-Jenkins", "kbn-version", "X-Drupal-Cache", "Server-Timing", "X-Amz-Cf-Id",
        "X-Kubernetes-Pf-Flowschema-Uid", "X-Envoy-Upstream-Service-Time", "X-Application-Context"
    ];

    public async Task<IReadOnlyList<WebServiceRow>> LatestAsync(Func<int, bool>? includeAsset = null, int? scanId = null, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var query = db.DiscoveredServices.AsNoTracking().Where(s => s.WebJson != null && s.Port!.Host!.Scan!.Status == ScanStatus.Completed);
        if (scanId is { } id) query = query.Where(s => s.Port!.Host!.ScanId == id);
        var rows = await query
            .Select(s => new
            {
                s.Id, s.WebJson, s.Port!.Port, s.Port.Host!.ScanId, At = s.Port.Host.Scan!.StartedAt ?? s.Port.Host.Scan.CreatedAt, s.Port.Host.AssetId, s.Port.Host.IpAddress,
                Name = s.Port.Host.Asset != null ? s.Port.Host.Asset.CustomName ?? s.Port.Host.Asset.DisplayName : s.Port.Host.IpAddress
            })
            .ToListAsync(ct);
        var latest = rows.GroupBy(r => (r.AssetId ?? -r.Id, r.Port)).Select(g => g.MaxBy(r => r.At)!)
            .Where(r => r.AssetId is not { } a || includeAsset?.Invoke(a) != false).ToList();
        var ids = latest.Select(r => r.Id).ToList();
        var technologies = (await db.ServiceTechnologies.AsNoTracking().Where(t => ids.Contains(t.DiscoveredServiceId)).ToListAsync(ct))
            .GroupBy(t => t.DiscoveredServiceId).ToDictionary(g => g.Key, g => g.Select(t => new TechnologyView(t.SignatureId, t.Name, t.Category, t.Version, t.Confidence, t.Evidence))
                .OrderBy(t => t.Category).ThenByDescending(t => t.Confidence).ToList());

        var result = new List<WebServiceRow>();
        foreach (var r in latest)
        {
            if (SignatureService.Observation(r.WebJson) is not { } web) continue;
            var tech = technologies.GetValueOrDefault(r.Id) ?? [];
            var headers = InterestingHeaderNames.Where(h => web.Header(h) is not null).Select(h => $"{h}: {web.Header(h)}").ToList();
            var isTls = web.Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            var cookieIssues = web.Cookies.SelectMany(c => (IEnumerable<string>)[
                .. !c.HttpOnly ? [$"{c.Name}: brak HttpOnly"] : Array.Empty<string>(),
                .. isTls && !c.Secure ? [$"{c.Name}: brak Secure"] : Array.Empty<string>()]).ToList();
            var (interest, reasons) = Interest(tech, headers, cookieIssues, web);
            result.Add(new WebServiceRow(r.Id, r.ScanId, r.At, r.AssetId, r.Name, r.IpAddress, r.Port, web, tech, interest, reasons, headers, cookieIssues));
        }

        return result.OrderByDescending(r => r.Interest).ThenBy(r => r.Ip, StringComparer.Ordinal).ThenBy(r => r.Port).ToList();
    }

    /// <summary>A transparent, additive score – every point is explained.</summary>
    internal static (int Score, IReadOnlyList<string> Reasons) Interest(IReadOnlyList<TechnologyView> tech, IReadOnlyList<string> headers, IReadOnlyList<string> cookieIssues, WebObservation web)
    {
        var reasons = new List<string>();
        var score = 0;
        void Add(int points, string why)
        {
            score += points;
            reasons.Add($"+{points} {why}");
        }

        if (tech.Any(t => t.SignatureId == "debug-mode")) Add(35, "tryb debugowania aplikacji");
        if (tech.Any(t => t.Category == SignatureCategory.AdminPanel)) Add(30, "panel administracyjny: " + string.Join(", ", tech.Where(t => t.Category == SignatureCategory.AdminPanel).Select(t => t.Name).Distinct()));
        if (tech.Any(t => t.Category == SignatureCategory.Staging && t.SignatureId != "debug-mode")) Add(25, "środowisko testowe / staging");
        if (tech.Any(t => t.SignatureId == "directory-listing")) Add(20, "listowanie katalogu");
        if (tech.Any(t => t.Category == SignatureCategory.Cms)) Add(10, "CMS: " + string.Join(", ", tech.Where(t => t.Category == SignatureCategory.Cms).Select(t => t.Name + (t.Version is null ? "" : " " + t.Version))));
        if (tech.Any(t => t.Category == SignatureCategory.Iot)) Add(10, "urządzenie IoT");
        if (tech.Any(t => t.Version is not null)) Add(10, "ujawniona wersja oprogramowania");
        if (headers.Count > 0) Add(Math.Min(10, 3 * headers.Count), $"ciekawe nagłówki ({headers.Count})");
        if (cookieIssues.Count > 0) Add(5, "ciasteczka bez flag bezpieczeństwa");
        if (tech.Any(t => t.SignatureId == "default-page")) Add(5, "domyślna strona serwera");
        if (web.Status is 401 or 403) Add(5, $"dostęp zablokowany (HTTP {web.Status}) – coś jest chronione");
        return (Math.Min(100, score), reasons);
    }
}
