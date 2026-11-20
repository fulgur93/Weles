using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Queries;
using Weles.Infrastructure.Settings;

namespace Weles.Infrastructure.AI;

/// <summary>Data given to the model for one question, and the list of what it contains (shown to the user).</summary>
public sealed record AiContext(string Text, IReadOnlyList<string> Sources);

/// <summary>Optional focus chosen in the UI (e.g. "Explain with the AI Analyst" on a CVE or device page).</summary>
public sealed record AiFocus(string? CveId = null, int? AssetId = null);

/// <summary>
/// Builds the data block for a question from the WELES database only – the model never sees anything else and is told
/// to answer from it. Always: networks, Security Posture Score, top priorities and riskiest devices. Depending on the
/// question: CVE details, a device's services and risk, changes between the last two scans, the full device list.
/// Values from the network (banners, page titles, names) are sanitised and clipped: they are data, never instructions.
/// </summary>
public sealed partial class AiContextBuilder(
    IDbContextFactory<WelesDbContext> contextFactory,
    RiskQueries risk,
    VulnerabilityQueries vulnerabilities,
    AssetQueries assets,
    SettingsService settings,
    MonitoringQueries? monitoring = null,
    TopologyQueries? topology = null)
{
    public const int MaxContextChars = 7_000;

    public async Task<AiContext> BuildAsync(string question, AiFocus? focus = null, CancellationToken ct = default)
    {
        var sb = new StringBuilder();
        var sources = new List<string>();
        var q = question.ToLowerInvariant();

        await AppendOverviewAsync(sb, sources, ct);

        var cves = CveRx().Matches(question).Select(m => m.Value.ToUpperInvariant()).Append(focus?.CveId?.ToUpperInvariant()).OfType<string>().Distinct().Take(3).ToList();
        foreach (var cve in cves) await AppendCveAsync(sb, sources, cve, ct);

        var assetIds = await MentionedAssetsAsync(question, focus?.AssetId, ct);
        foreach (var id in assetIds.Take(3)) await AppendAssetAsync(sb, sources, id, ct);
        await AppendMissingTypesAsync(sb, sources, q, ct);

        if (Mentions(q, ChangeWords)) await AppendChangesAsync(sb, sources, ct);
        if (Mentions(q, InventoryWords)) await AppendInventoryAsync(sb, sources, ct);
        if (Mentions(q, PathWords)) await AppendPathsAsync(sb, sources, ct);

        var text = sb.ToString();
        if (text.Length > MaxContextChars) text = text[..MaxContextChars] + "\n[… dane skrócone do limitu kontekstu]";
        return new AiContext(text, sources);
    }

    private static readonly string[] ChangeWords = ["zmian", "zmieni", "nowe", "nowych", "nowy ", "pojawi", "znikn", "od ostatniego", "poprzedni", "change", "new device", "since", "appeared", "disappeared"];
    private static readonly string[] InventoryWords = ["raport", "podsumow", "audyt", "wszystkie urządzenia", "lista urządzeń", "inwentarz", "report", "summary", "audit", "all devices", "inventory"];

    private static readonly string[] PathWords = ["ścieżk", "sciezk", "atak", "dotrzeć", "przejąć", "path", "attack", "reach"];

    private static bool Mentions(string q, string[] words) => words.Any(q.Contains);

    private async Task AppendOverviewAsync(StringBuilder sb, List<string> sources, CancellationToken ct)
    {
        var overview = await risk.OverviewAsync(ct);
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var assetCount = await db.Assets.CountAsync(ct);
        var lastScan = await db.Scans.AsNoTracking().Where(s => s.Status == ScanStatus.Completed).OrderByDescending(s => s.StartedAt)
            .Select(s => new { s.Id, s.StartedAt, s.PortSpecification, Name = s.ScanTarget!.Name }).FirstOrDefaultAsync(ct);
        var vulnDb = await settings.GetAsync(SettingsService.Keys.VulnerabilityDatabaseUpdatedAt, ct);

        sb.AppendLine("## Stan infrastruktury");
        sb.AppendLine($"- urządzeń w inwentarzu: {assetCount}");
        if (lastScan is not null) sb.AppendLine($"- ostatni skan: #{lastScan.Id} „{Clean(lastScan.Name, 80)}” {lastScan.StartedAt:yyyy-MM-dd HH:mm} UTC, profil portów: {lastScan.PortSpecification}");
        else sb.AppendLine("- nie wykonano jeszcze żadnego skanu");
        sb.AppendLine($"- baza podatności (NVD/CISA KEV/EPSS) z: {(vulnDb is null ? "brak" : vulnDb[..Math.Min(10, vulnDb.Length)])}");
        sb.AppendLine("- dostępność z Internetu: NIEZNANA – nie była badana (skany z sieci lokalnej); nie wolno pisać ani że coś jest, ani że nie jest dostępne z Internetu");
        foreach (var n in overview.Networks)
        {
            sb.AppendLine($"- sieć {Clean(n.Latest.Network ?? "bez rozpoznanej bramy", 80)}: Security Posture Score {n.Latest.Score:0}/100 (skan #{n.Latest.ScanId}{(n.Previous is { } p ? $", poprzednio {p:0}" : "")}); urządzenia wg poziomu: " +
                string.Join(", ", n.Breakdown.AssetsByLevel.Where(kv => kv.Value > 0).Select(kv => $"{kv.Key} {kv.Value}")));
        }

        sources.Add("stan sieci i Security Posture Score");

        if (overview.Priorities.Count > 0)
        {
            sb.AppendLine("\n## Priorytety napraw (od najważniejszego)");
            foreach (var (item, i) in overview.Priorities.Take(4).Select((p, i) => (p, i + 1)))
            {
                sb.AppendLine($"{i}. [{item.Level}, priorytet {item.Priority:0}] {Clean(item.Issue.Title, 120)} – urządzenie: {Clean(item.AssetName, 80)} ({item.AssetIp})");
                sb.AppendLine($"   powody: {Clean(string.Join("; ", item.Issue.Reasons.Concat(item.Context.Select(c => c.Text))), 260)}");
                if (item.Issue.CveIds is { Count: > 0 } ids)
                {
                    var facts = await CveFactsAsync(item.AssetId, ids, ct);
                    sb.AppendLine($"   CVE ({ids.Count}): {string.Join(", ", ids.Take(5))}{(ids.Count > 5 ? ", …" : "")}");
                    if (facts.TopDescription is not null) sb.AppendLine($"   najpoważniejsza wg NVD (angielski): {facts.TopDescription}");
                    sb.AppendLine($"   pewność dopasowania: {facts.Certainty}");
                    sb.AppendLine($"   w katalogu CISA KEV (wykorzystywane w atakach): {(facts.Kev.Count == 0 ? "żadna" : string.Join(", ", facts.Kev))}");
                    if (facts.FixedFrom is not null) sb.AppendLine($"   wersja bez tych CVE wg NVD: {facts.FixedFrom} lub nowsza (albo aktualizacje bezpieczeństwa dystrybucji)");
                }
                else if (item.Issue.RuleId == Weles.Core.Risk.RiskRules.AdminPanelExposed.Id)
                {
                    sb.AppendLine("   uwaga: WELES nie wie, czy panel wymaga hasła – nie pisz, że działa bez uwierzytelnienia; ryzyko polega na tym, że panel jest osiągalny z sieci");
                }

                sb.AppendLine($"   zalecenie WELES: {Clean(item.Issue.Recommendation, 200)}");
            }

            sources.Add($"priorytety napraw ({Math.Min(4, overview.Priorities.Count)})");
        }

        if (overview.Assets.Count > 0)
        {
            sb.AppendLine("\n## Urządzenia o najwyższym ryzyku");
            foreach (var a in overview.Assets.Take(6))
            {
                sb.AppendLine($"- {Clean(a.Name, 80)} ({a.Ip}), typ {a.Type}, krytyczność {a.Criticality}: ryzyko {a.Score:0} ({a.Level}), problemów {a.Issues}, w KEV {a.KnownExploited}" +
                              (a.TopIssue is null ? "" : $"; najpoważniejszy: {Clean(a.TopIssue, 120)}"));
            }

            sources.Add($"ranking ryzyka urządzeń ({Math.Min(6, overview.Assets.Count)})");
        }
    }

    private sealed record CveFacts(string Certainty, List<string> Kev, string? FixedFrom, string? TopDescription);

    /// <summary>
    /// Facts a small model gets wrong when it has to infer them: certainty of the matches in words, which CVEs are in
    /// CISA KEV, and the first version without all these CVEs (highest upper bound of the NVD ranges).
    /// </summary>
    private async Task<CveFacts> CveFactsAsync(int assetId, IReadOnlyList<string> cveIds, CancellationToken ct)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var rows = await db.AssetVulnerabilities.AsNoTracking().Where(v => v.AssetId == assetId && cveIds.Contains(v.Vulnerability!.CveId))
            .Select(v => new { v.Vulnerability!.CveId, v.Vulnerability.IsKnownExploited, v.MatchStatus, v.VulnerabilityId, v.Product }).ToListAsync(ct);
        var certainty = string.Join(", ", rows.GroupBy(r => r.MatchStatus).OrderBy(g => g.Key).Select(g => $"{CertaintyWords(g.Key)}: {g.Count()}"));
        var product = Weles.Core.Rules.ProductCatalog.Find(rows.FirstOrDefault()?.Product ?? "");
        var ids = rows.Select(r => r.VulnerabilityId).ToList();
        var bounds = product is null ? [] : await db.VulnerabilityAffectedProducts.AsNoTracking()
            .Where(p => ids.Contains(p.VulnerabilityId) && (p.VersionEndExcluding != null || p.VersionEndIncluding != null))
            .Select(p => new { p.Vendor, p.Product, p.VersionEndExcluding, p.VersionEndIncluding }).ToListAsync(ct);
        string? fixedFrom = null;
        foreach (var b in bounds.Where(b => product!.AllCpes.Contains((b.Vendor, b.Product))))
        {
            var candidate = b.VersionEndExcluding ?? b.VersionEndIncluding;
            var label = b.VersionEndExcluding is not null ? b.VersionEndExcluding : $"nowsza niż {b.VersionEndIncluding}";
            if (fixedFrom is null || Weles.Core.Vulnerabilities.VersionComparer.Compare(candidate!, FixedVersion(fixedFrom)) > 0) fixedFrom = label;
        }

        // What the most serious CVE actually is (first sentence from NVD) – otherwise a small model fills it in from memory.
        var top = cveIds[0];
        var description = await db.Vulnerabilities.AsNoTracking().Where(v => v.CveId == top).Select(v => v.Description).FirstOrDefaultAsync(ct);
        var firstSentence = description is null ? null : FirstSentence(description);
        return new CveFacts(certainty.Length == 0 ? "brak danych" : certainty, rows.Where(r => r.IsKnownExploited).Select(r => r.CveId).Distinct().ToList(), fixedFrom,
            firstSentence is null ? null : $"{top}: {Clean(firstSentence, 260)}");
    }

    private static string FirstSentence(string text)
    {
        var end = text.IndexOf(". ", StringComparison.Ordinal);
        return end > 0 ? text[..(end + 1)] : text;
    }

    private static string FixedVersion(string label) => label.StartsWith("nowsza niż ", StringComparison.Ordinal) ? label["nowsza niż ".Length..] : label;

    private static string CertaintyWords(VulnerabilityMatchStatus status) => status switch
    {
        VulnerabilityMatchStatus.Confirmed => "potwierdzone",
        VulnerabilityMatchStatus.Probable => "prawdopodobne",
        VulnerabilityMatchStatus.NeedsVerification => "WYMAGA WERYFIKACJI (np. dystrybucja mogła przenieść poprawki bez zmiany wersji – to nie jest pewna podatność)",
        _ => "za mało danych"
    };

    /// <summary>"Is my NAS…?" when there is no NAS – the model must say so instead of answering about a device that does not exist.</summary>
    private async Task AppendMissingTypesAsync(StringBuilder sb, List<string> sources, string q, CancellationToken ct)
    {
        var asked = TypeWords.Where(t => q.Contains(t.Word)).Select(t => t.Type).Distinct().ToList();
        if (asked.Count == 0) return;
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var present = await db.Assets.AsNoTracking().Select(a => a.UserAssetType ?? a.AssetType).Distinct().ToListAsync(ct);
        foreach (var type in asked.Where(t => !present.Contains(t)))
        {
            sb.AppendLine($"\n## Brak urządzenia typu {type}");
            sb.AppendLine($"- w inwentarzu WELES NIE MA żadnego urządzenia typu {type}; odpowiedz, że takiego urządzenia nie wykryto (może nie było skanowane albo ma inny typ – użytkownik może ustawić typ ręcznie w szczegółach urządzenia)");
            sources.Add($"brak urządzeń typu {type} w inwentarzu");
        }
    }

    private async Task AppendCveAsync(StringBuilder sb, List<string> sources, string cveId, CancellationToken ct)
    {
        var d = await vulnerabilities.GetCveAsync(cveId, ct);
        sb.AppendLine($"\n## {cveId}");
        if (d is null)
        {
            sb.AppendLine("- brak tej podatności w lokalnej bazie WELES (nie wolno nic o niej zakładać)");
            sources.Add($"{cveId} – brak w bazie");
            return;
        }

        var v = d.Vulnerability;
        sb.AppendLine($"- opis z NVD (angielski): {Clean(v.Description, 900)}");
        sb.AppendLine($"- CVSS {v.CvssScore?.ToString("0.0", CultureInfo.InvariantCulture) ?? "brak"} {v.CvssVector}; EPSS {(v.EpssScore is { } e ? (e * 100).ToString("0.##", CultureInfo.InvariantCulture) + "%" : "brak")}; CISA KEV: {(v.IsKnownExploited ? $"TAK (od {v.KevDateAdded:yyyy-MM-dd}{(v.KevRansomwareUse ? ", używana przez ransomware" : "")})" : "nie")}; opublikowana {v.PublishedAt:yyyy-MM-dd}; CWE: {v.Weaknesses ?? "brak"}");
        var affected = v.AffectedProducts.Take(6).Select(p => $"{p.Vendor}:{p.Product} " + Range(p)).ToList();
        if (affected.Count > 0) sb.AppendLine($"- podatne wersje wg NVD: {string.Join("; ", affected)}{(v.AffectedProducts.Count > 6 ? "; …" : "")}");
        if (d.Findings.Count == 0) sb.AppendLine("- w sieci użytkownika nie dopasowano żadnego urządzenia");
        foreach (var f in d.Findings.Take(5))
        {
            sb.AppendLine($"- dopasowane urządzenie: {Clean(f.AssetName, 80)} ({f.AssetIp}), {f.Product} {f.DetectedVersion}{(f.Port is { } port ? $" port {port}" : "")}, pewność dopasowania: {CertaintyWords(f.MatchStatus)} ({f.MatchConfidence}%), stan: {f.Status}");
            sb.AppendLine($"  uzasadnienie: {Clean(f.MatchReason, 400)}");
        }

        sources.Add($"{cveId} – opis NVD, CVSS, EPSS, KEV, dopasowane urządzenia ({d.Findings.Count})");
    }

    private static string Range(VulnerabilityAffectedProduct p)
    {
        if (p.Version is not null) return "= " + p.Version;
        var parts = new List<string>();
        if (p.VersionStartIncluding is not null) parts.Add("≥ " + p.VersionStartIncluding);
        if (p.VersionStartExcluding is not null) parts.Add("> " + p.VersionStartExcluding);
        if (p.VersionEndIncluding is not null) parts.Add("≤ " + p.VersionEndIncluding);
        if (p.VersionEndExcluding is not null) parts.Add("< " + p.VersionEndExcluding);
        return parts.Count == 0 ? "(wszystkie wersje)" : string.Join(", ", parts);
    }

    private async Task<List<int>> MentionedAssetsAsync(string question, int? focusId, CancellationToken ct)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var all = await db.Assets.AsNoTracking().Select(a => new { a.Id, a.DisplayName, a.CustomName, a.Hostname, a.PrimaryIpAddress, a.Model, a.AssetType, a.UserAssetType, a.CurrentRiskScore }).ToListAsync(ct);
        var q = question.ToLowerInvariant();
        var ids = new List<int>();
        if (focusId is { } f && all.Any(a => a.Id == f)) ids.Add(f);

        var ips = IpRx().Matches(question).Select(m => m.Value).ToHashSet();
        foreach (var a in all.OrderByDescending(a => a.CurrentRiskScore ?? 0))
        {
            var names = new[] { a.CustomName, a.Hostname, a.Model, a.DisplayName }.Where(n => n is { Length: >= 4 }).Select(n => n!.ToLowerInvariant());
            if ((a.PrimaryIpAddress is not null && ips.Contains(a.PrimaryIpAddress)) || names.Any(q.Contains)) ids.Add(a.Id);
        }

        // "mój NAS", "router", "drukarka" – devices of that type.
        foreach (var (word, type) in TypeWords)
        {
            if (!q.Contains(word)) continue;
            ids.AddRange(all.Where(a => (a.UserAssetType ?? a.AssetType) == type).OrderByDescending(a => a.CurrentRiskScore ?? 0).Select(a => a.Id).Take(2));
        }

        return ids.Distinct().ToList();
    }

    private static readonly (string Word, AssetType Type)[] TypeWords =
    [
        ("nas", AssetType.Nas), ("router", AssetType.Router), ("drukark", AssetType.Printer), ("printer", AssetType.Printer),
        ("kamer", AssetType.IpCamera), ("camera", AssetType.IpCamera), ("serwer", AssetType.Server), ("server", AssetType.Server),
        ("telefon", AssetType.MobileDevice), ("phone", AssetType.MobileDevice)
    ];

    private async Task AppendAssetAsync(StringBuilder sb, List<string> sources, int assetId, CancellationToken ct)
    {
        var detail = await assets.GetAsync(assetId, ct);
        if (detail is null) return;
        var a = detail.Asset;
        sb.AppendLine($"\n## Urządzenie: {Clean(a.CustomName ?? a.DisplayName, 80)}");
        sb.AppendLine($"- adres {a.PrimaryIpAddress}, MAC {a.MacAddress ?? "brak"}, producent {Clean(a.Vendor ?? "nieznany", 80)}{(a.Model is null ? "" : $", model {Clean(a.Model, 60)}")}, typ {a.EffectiveType}, system {a.OsFamily ?? "nieznany"}, krytyczność (ustawiona przez użytkownika) {a.Criticality}");
        sb.AppendLine($"- obecność: {detail.Presence.Status}; pierwsze wykrycie {a.FirstSeenAt:yyyy-MM-dd}, ostatnio {a.LastSeenAt:yyyy-MM-dd}");
        foreach (var p in detail.CurrentPorts.OrderBy(p => p.Port).Take(15))
        {
            var s = p.Service;
            sb.AppendLine($"- port {p.Port}/tcp: {s?.ServiceName ?? "?"}{(s?.Product is null ? "" : $" – {Clean(s.Product, 60)} {Clean(s.Version ?? "", 30)}")} (pewność rozpoznania {s?.Confidence ?? 0}%){(s?.IsTls == true ? ", TLS" : "")}");
        }

        if (await risk.AssetAsync(assetId, ct) is { } r)
        {
            sb.AppendLine($"- ocena ryzyka WELES: {r.Result.Score:0}/100 ({r.Result.Level}); składniki: {Clean(string.Join("; ", r.Result.Factors.Select(f => $"{f.Text} ({f.Points:+0.#;-0.#;0})")), 700)}");
            foreach (var i in r.Result.Issues.Take(6))
            {
                sb.AppendLine($"  - problem [{i.Level}, {i.Score:0}]: {Clean(i.Title, 120)}; {Clean(string.Join("; ", i.Reasons), 300)}{(i.CveIds is { Count: > 0 } c ? $"; CVE: {string.Join(", ", c.Take(5))}{(c.Count > 5 ? $" (+{c.Count - 5})" : "")}" : "")}");
            }
        }

        sources.Add($"urządzenie {a.CustomName ?? a.DisplayName} – usługi, wersje, ocena ryzyka");
    }

    private async Task AppendChangesAsync(StringBuilder sb, List<string> sources, CancellationToken ct)
    {
        sb.AppendLine("\n## Zmiany między dwoma ostatnimi skanami tej samej sieci");
        var c = monitoring is null ? null : await monitoring.LatestAsync(ct);
        if (c is null)
        {
            sb.AppendLine("- za mało skanów tej sieci do porównania");
            sources.Add("zmiany – za mało skanów");
            return;
        }

        static string Devices(IEnumerable<DeviceRef> d) => string.Join(", ", d.Select(x => $"{Clean(x.Name, 50)} ({x.Ip})")) is { Length: > 0 } s ? s : "brak";
        sb.AppendLine($"- porównanie: skan #{c.Previous.Id} ({c.Previous.At:yyyy-MM-dd HH:mm}) → #{c.Current.Id} ({c.Current.At:yyyy-MM-dd HH:mm}) UTC; profile portów {c.Previous.PortSpecification} → {c.Current.PortSpecification}");
        sb.AppendLine($"- nowe urządzenia (pierwszy raz): {Devices(c.NewDevices)}");
        if (c.ReturnedDevices.Count > 0) sb.AppendLine($"- pojawiły się ponownie: {Devices(c.ReturnedDevices)}");
        sb.AppendLine($"- nie wykryto w ostatnim skanie (adres był w zakresie): {Devices(c.MissingDevices)}");
        foreach (var d in c.Changed.Take(8))
        {
            sb.AppendLine($"- {Clean(d.Device.Name, 50)} ({d.Device.Ip}): {Clean(string.Join("; ", d.Changes.Select(x => x.Description)), 300)}");
        }

        sb.AppendLine($"- nowe dopasowane podatności: {(c.NewVulnerabilities.Count == 0 ? "brak" : string.Join(", ", c.NewVulnerabilities.Take(6).Select(v => $"{v.CveId} na {Clean(v.Device.Name, 40)}")) + (c.NewVulnerabilities.Count > 6 ? $" (razem {c.NewVulnerabilities.Count})" : ""))}");
        sb.AppendLine($"- rozwiązane podatności: {(c.ResolvedVulnerabilities.Count == 0 ? "brak" : c.ResolvedVulnerabilities.Count.ToString())}");
        if (c.PostureBefore is { } pb && c.PostureAfter is { } pa) sb.AppendLine($"- Security Posture Score: {pb:0} → {pa:0}");
        sb.AppendLine("- porty są porównywane tylko, gdy oba skany je sprawdzały");
        sources.Add($"zmiany między skanami #{c.Previous.Id} i #{c.Current.Id}");
    }

    private async Task AppendPathsAsync(StringBuilder sb, List<string> sources, CancellationToken ct)
    {
        if (topology is null) return;
        var paths = await topology.AttackPathsAsync(ct);
        sb.AppendLine("\n## Potencjalne ścieżki ataku (HIPOTEZY, nie potwierdzone ataki)");
        if (paths.Count == 0) sb.AppendLine("- brak: żadne urządzenie nie ma problemu co najmniej średniej wagi");
        foreach (var p in paths.Take(3))
        {
            sb.AppendLine($"- {Clean(p.Title, 140)} (priorytet {p.Priority:0}, pewność ścieżki {p.Confidence}%)");
            foreach (var step in p.Steps) sb.AppendLine($"  - {step.Kind}: {Clean(step.Title, 120)} – {(step.Confidence is { } c ? $"pewność {c}%" : "założenie")}");
        }

        sources.Add($"ścieżki ataku ({Math.Min(3, paths.Count)})");
    }

    private async Task AppendInventoryAsync(StringBuilder sb, List<string> sources, CancellationToken ct)
    {
        var page = await assets.QueryAsync(new AssetListQuery { PageSize = 25, Sort = [new(AssetSortColumn.Risk, true)] }, ct);
        sb.AppendLine("\n## Wszystkie urządzenia (inwentarz)");
        foreach (var a in page.Items)
        {
            sb.AppendLine($"- {Clean(a.DisplayName, 60)} ({a.IpAddress}), {a.Type}, {a.OsFamily ?? "system nieznany"}, porty {string.Join(",", a.OpenPorts.Take(8))}, oprogramowanie {Clean(string.Join(", ", a.Products.Take(3)), 120)}, ryzyko {(a.RiskScore is { } r ? r.ToString("0") : "brak")}, status {a.Status}");
        }

        sources.Add($"inwentarz urządzeń ({page.Items.Count})");
    }

    /// <summary>Network-provided text: one line, no control characters, clipped – it can never look like a new instruction block.</summary>
    internal static string Clean(string? value, int max)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var sb = new StringBuilder(Math.Min(value.Length, max));
        foreach (var c in value)
        {
            if (sb.Length >= max) break;
            sb.Append(char.IsControl(c) ? ' ' : c is '`' or '#' ? '\'' : c);
        }

        var s = sb.ToString().Trim();
        return value.Length > max ? s + "…" : s;
    }

    [GeneratedRegex(@"CVE-\d{4}-\d{4,}", RegexOptions.IgnoreCase)]
    private static partial Regex CveRx();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b")]
    private static partial Regex IpRx();
}
