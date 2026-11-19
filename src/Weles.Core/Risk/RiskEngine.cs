using Weles.Core.Enums;

namespace Weles.Core.Risk;

/// <summary>A CVE matched to the asset, with what the risk engine needs from it.</summary>
public sealed record VulnerabilityFacts(
    string CveId,
    double? CvssScore,
    double? EpssScore,
    bool IsKnownExploited,
    VulnerabilityMatchStatus MatchStatus,
    int? Port,
    string? Product,
    string? Version,
    DateTime? PublishedAt);

/// <summary>Everything the engine knows about one device at the time of a scan.</summary>
public sealed record AssetRiskInput(
    AssetType Type,
    AssetCriticality Criticality,
    bool IsGateway,
    bool HasPublicAddress,
    int OpenPortCount,
    IReadOnlyList<ConfigFinding> ConfigFindings,
    IReadOnlyList<VulnerabilityFacts> Vulnerabilities,
    IReadOnlyList<int> NewlyOpenedPorts,
    int AcceptedCount = 0);

/// <summary>One line of the score explanation. <see cref="Points"/> is what it added (or, for a multiplier, the change).</summary>
public sealed record RiskFactor(string Kind, string Text, double Points);

/// <summary>A problem to fix: a configuration finding, or all CVEs of one product on one port.</summary>
public sealed record RiskIssue(
    string Key,
    string Kind,
    string Title,
    double Score,
    RiskLevel Level,
    int? Port,
    string Recommendation,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<string> AttackTechniques,
    string? RuleId = null,
    IReadOnlyList<string>? CveIds = null,
    int KnownExploited = 0);

public sealed record AssetRiskResult(double Score, RiskLevel Level, IReadOnlyList<RiskFactor> Factors, IReadOnlyList<RiskIssue> Issues);

public sealed record PostureResult(double Score, IReadOnlyList<RiskFactor> Factors, IReadOnlyDictionary<RiskLevel, int> AssetsByLevel);

/// <summary>
/// WELES risk scoring – deliberately simple enough to explain on one screen:
/// <list type="number">
/// <item>Each issue gets 0–100: CVSS × 10 (+20 CISA KEV, +4…15 EPSS), scaled by how certain the match is; configuration
/// findings start from the rule's base score.</item>
/// <item>The device starts from its worst issue, plus 10% of each further issue (at most +15).</item>
/// <item>Context: × business criticality, + role in the infrastructure, + exposure (public address, UPnP), + number of
/// services, + age of the software (oldest unpatched CVE), + recent changes.</item>
/// <item>Level: ≥ 80 Critical, ≥ 60 High, ≥ 35 Medium, ≥ 15 Low, otherwise Informational.</item>
/// </list>
/// Every step is returned as a <see cref="RiskFactor"/> – the score is never shown without its reasons.
/// </summary>
public static class RiskEngine
{
    public static RiskLevel LevelOf(double score) => score switch
    {
        >= 80 => RiskLevel.Critical,
        >= 60 => RiskLevel.High,
        >= 35 => RiskLevel.Medium,
        >= 15 => RiskLevel.Low,
        _ => RiskLevel.Informational
    };

    public static double MatchWeight(VulnerabilityMatchStatus status) => status switch
    {
        VulnerabilityMatchStatus.Confirmed => 1.0,
        VulnerabilityMatchStatus.Probable => 0.85,
        VulnerabilityMatchStatus.NeedsVerification => 0.6,
        _ => 0.25
    };

    public static double CriticalityMultiplier(AssetCriticality c) => c switch
    {
        AssetCriticality.Low => 0.8,
        AssetCriticality.High => 1.15,
        AssetCriticality.Critical => 1.3,
        _ => 1.0
    };

    /// <summary>Score of a single CVE on this device, with its reasons.</summary>
    public static (double Score, List<string> Reasons) ScoreVulnerability(VulnerabilityFacts v)
    {
        var reasons = new List<string>();
        var score = (v.CvssScore ?? 5.0) * 10;
        reasons.Add(v.CvssScore is { } cvss ? $"CVSS {cvss:0.0}" : "brak CVSS – przyjęto 5.0");
        if (v.IsKnownExploited)
        {
            score += 20;
            reasons.Add("w katalogu CISA KEV – wykorzystywana w atakach (+20)");
        }

        if (v.EpssScore is { } epss)
        {
            var bonus = epss >= 0.5 ? 15 : epss >= 0.1 ? 10 : epss >= 0.01 ? 4 : 0;
            if (bonus > 0)
            {
                score += bonus;
                reasons.Add($"EPSS {epss * 100:0.#}% – prawdopodobieństwo wykorzystania w 30 dni (+{bonus})");
            }
        }

        var weight = MatchWeight(v.MatchStatus);
        if (weight < 1)
        {
            score *= weight;
            reasons.Add($"pewność dopasowania: × {weight:0.##}");
        }

        return (Math.Clamp(score, 0, 100), reasons);
    }

    public static AssetRiskResult ScoreAsset(AssetRiskInput input, DateTime now)
    {
        var issues = new List<RiskIssue>();

        // CVEs grouped by product and port: one upgrade fixes them together.
        foreach (var group in input.Vulnerabilities.GroupBy(v => (v.Port, v.Product, v.Version)))
        {
            var scored = group.Select(v => (v, s: ScoreVulnerability(v))).OrderByDescending(x => x.s.Score).ToList();
            var top = scored[0];
            var extra = Math.Min(10, scored.Count - 1);
            var score = Math.Clamp(top.s.Score + extra, 0, 100);
            var kev = scored.Count(x => x.v.IsKnownExploited);
            // Separate lines, not one composite sentence – each is shown (and translated) on its own.
            var reasons = new List<string> { $"najpoważniejsza: {top.v.CveId}" };
            reasons.AddRange(top.s.Reasons);
            if (extra > 0) reasons.Add($"{scored.Count} podatności tego oprogramowania (+{extra})");
            if (kev > 0) reasons.Add($"{kev} w katalogu CISA KEV");
            var hardware = group.Key.Port is null;
            var what = $"{group.Key.Product} {group.Key.Version}".Trim();
            issues.Add(new RiskIssue(
                $"cve:{group.Key.Port}:{group.Key.Product}",
                "vulnerability",
                hardware ? $"Sprawdź firmware: {what}" : $"Zaktualizuj {what} (port {group.Key.Port})",
                Math.Round(score, 1), LevelOf(score), group.Key.Port,
                hardware
                    ? "Sprawdź wersję oprogramowania układowego w panelu urządzenia i zainstaluj najnowszą wersję od producenta."
                    : "Zaktualizuj oprogramowanie do wersji bez tych podatności; dla pakietów dystrybucji zainstaluj aktualizacje bezpieczeństwa i sprawdź biuletyn (poprawki przenoszone bez zmiany wersji).",
                reasons,
                kev > 0 ? ["T1190", "T1210"] : ["T1210"],
                CveIds: scored.Select(x => x.v.CveId).ToList(),
                KnownExploited: kev));
        }

        foreach (var f in input.ConfigFindings)
        {
            var score = f.Rule.BaseScore * (f.Confidence < 70 ? 0.8 : 1.0);
            var reasons = new List<string> { f.Evidence };
            if (f.Confidence < 70) reasons.Add($"usługa rozpoznana tylko po numerze portu: × 0.8");
            issues.Add(new RiskIssue($"rule:{f.Rule.Id}:{f.Port}", "configuration", f.Rule.Title, Math.Round(score, 1), LevelOf(score), f.Port,
                f.Rule.Recommendation, reasons, f.Rule.AttackTechniques, RuleId: f.Rule.Id));
        }

        issues = issues.OrderByDescending(i => i.Score).ThenBy(i => i.Key, StringComparer.Ordinal).ToList();

        var factors = new List<RiskFactor>();
        double total = 0;
        if (issues.Count > 0)
        {
            total = issues[0].Score;
            factors.Add(new RiskFactor("top-issue", $"najpoważniejszy problem: {issues[0].Title}", total));
            if (issues.Count > 1)
            {
                var more = Math.Min(15, issues.Skip(1).Sum(i => i.Score) * 0.1);
                total += more;
                factors.Add(new RiskFactor("more-issues", $"kolejne problemy: {issues.Count - 1} (10% ich punktów, maks. 15)", Math.Round(more, 1)));
            }
        }
        else
        {
            factors.Add(new RiskFactor("no-issues", "brak wykrytych problemów i dopasowanych podatności", 0));
        }

        var multiplier = CriticalityMultiplier(input.Criticality);
        if (multiplier != 1.0)
        {
            var before = total;
            total *= multiplier;
            factors.Add(new RiskFactor("criticality", $"krytyczność urządzenia: {CriticalityName(input.Criticality)} (× {multiplier:0.##})", Math.Round(total - before, 1)));
        }

        if (input.IsGateway || input.Type is AssetType.Router)
        {
            total += 8;
            factors.Add(new RiskFactor("role", "brama / router – przez niego przechodzi ruch całej sieci", 8));
        }
        else if (input.Type is AssetType.Server or AssetType.Nas or AssetType.Switch or AssetType.NetworkDevice)
        {
            total += 5;
            factors.Add(new RiskFactor("role", "urządzenie infrastruktury (serwer, NAS, urządzenie sieciowe)", 5));
        }

        if (input.HasPublicAddress)
        {
            total += 15;
            factors.Add(new RiskFactor("exposure", "adres publiczny – usługi mogą być dostępne z Internetu", 15));
        }
        else
        {
            factors.Add(new RiskFactor("exposure", "tylko sieć lokalna – dostępności z Internetu nie badano (Etap 8)", 0));
        }

        if ((input.IsGateway || input.Type is AssetType.Router) && input.ConfigFindings.Any(f => f.Rule.Id == RiskRules.Upnp.Id))
        {
            total += 5;
            factors.Add(new RiskFactor("exposure", "UPnP na routerze – programy w sieci mogą otwierać porty na zewnątrz", 5));
        }

        if (input.OpenPortCount > 5)
        {
            var services = Math.Min(8, input.OpenPortCount - 5);
            total += services;
            factors.Add(new RiskFactor("services", $"{input.OpenPortCount} otwartych portów – większa powierzchnia ataku", services));
        }

        var oldest = input.Vulnerabilities.Where(v => v.MatchStatus != VulnerabilityMatchStatus.InsufficientData && v.PublishedAt is not null).Select(v => v.PublishedAt!.Value).DefaultIfEmpty().Min();
        if (oldest != default)
        {
            var years = (now - oldest).TotalDays / 365.25;
            var age = years >= 5 ? 6 : years >= 2 ? 3 : 0;
            if (age > 0)
            {
                total += age;
                factors.Add(new RiskFactor("age", $"najstarsza niezałatana podatność opublikowana {oldest:yyyy} – oprogramowanie nieaktualizowane od ok. {Math.Floor(years):0} lat", age));
            }
        }

        if (input.NewlyOpenedPorts.Count > 0)
        {
            total += 5;
            factors.Add(new RiskFactor("changes", $"nowe porty od poprzedniego skanu: {string.Join(", ", input.NewlyOpenedPorts)}", 5));
        }

        if (input.AcceptedCount > 0)
        {
            factors.Add(new RiskFactor("accepted", $"zaakceptowane ryzyka nieliczone w ocenie: {input.AcceptedCount}", 0));
        }

        var final = Math.Round(Math.Clamp(total, 0, 100), 1);
        return new AssetRiskResult(final, LevelOf(final), factors, issues);
    }

    /// <summary>
    /// Security Posture Score of a network, 0–100, higher is better: 100 − (½ of the riskiest device + ½ of the average of
    /// the five riskiest). One very weak device lowers it a lot; many small issues lower it a little.
    /// </summary>
    public static PostureResult Posture(IReadOnlyList<(string Name, double Score)> assets)
    {
        var byLevel = Enum.GetValues<RiskLevel>().ToDictionary(l => l, l => assets.Count(a => LevelOf(a.Score) == l));
        if (assets.Count == 0)
        {
            return new PostureResult(100, [new RiskFactor("empty", "brak urządzeń w skanie", 0)], byLevel);
        }

        var ordered = assets.OrderByDescending(a => a.Score).ToList();
        var worst = ordered[0];
        var top5 = ordered.Take(5).Average(a => a.Score);
        var penalty = 0.5 * worst.Score + 0.5 * top5;
        var factors = new List<RiskFactor>
        {
            new("worst", $"najbardziej zagrożone urządzenie: {worst.Name} ({worst.Score:0})", -Math.Round(0.5 * worst.Score, 1)),
            new("top5", $"średnia {Math.Min(5, ordered.Count)} najbardziej zagrożonych urządzeń: {top5:0.#}", -Math.Round(0.5 * top5, 1))
        };
        foreach (var level in new[] { RiskLevel.Critical, RiskLevel.High })
        {
            if (byLevel[level] > 0) factors.Add(new RiskFactor("count", $"urządzenia z poziomem {LevelName(level)}: {byLevel[level]}", 0));
        }

        return new PostureResult(Math.Round(Math.Clamp(100 - penalty, 0, 100), 1), factors, byLevel);
    }

    private static string CriticalityName(AssetCriticality c) => c switch
    {
        AssetCriticality.Low => "niska",
        AssetCriticality.High => "wysoka",
        AssetCriticality.Critical => "krytyczna",
        _ => "średnia"
    };

    private static string LevelName(RiskLevel l) => l switch
    {
        RiskLevel.Critical => "Critical",
        RiskLevel.High => "High",
        RiskLevel.Medium => "Medium",
        RiskLevel.Low => "Low",
        _ => "Informational"
    };
}
