using Weles.Core.Enums;

namespace Weles.Core.Risk;

public enum PathStepKind
{
    /// <summary>Where an attacker is assumed to start – an assumption, not a finding.</summary>
    Entry,
    /// <summary>Network reachability observed by a scan.</summary>
    Access,
    /// <summary>A weakness found on the reachable service (CVE match or configuration).</summary>
    Weakness,
    /// <summary>What could follow if the weakness were used – always a hypothesis.</summary>
    Impact
}

/// <param name="Confidence">0–100: how sure WELES is that this step holds; null for the starting assumption.</param>
public sealed record PathStep(PathStepKind Kind, string Title, string Justification, int? Confidence, int? AssetId = null, int? Port = null, string? CveId = null);

/// <summary>
/// A potential exposure path. Always hypothetical: it shows a possible way to reach an asset based on what the scans saw,
/// never a confirmed attack – WELES does not try to exploit anything.
/// </summary>
public sealed record AttackPath(string Key, string Title, double Priority, RiskLevel Level, int Confidence, IReadOnlyList<PathStep> Steps, int TargetAssetId)
{
    public bool IsHypothetical => true;
}

/// <summary>A device as the path engine needs it: identity, role and its issues with evidence certainty.</summary>
public sealed record PathAsset(
    int AssetId,
    string Name,
    string? Ip,
    AssetType Type,
    AssetCriticality Criticality,
    bool IsGateway,
    bool HasPublicAddress,
    int ScanId,
    string Network,
    int DevicesOnNetwork,
    IReadOnlyList<PathIssue> Issues,
    bool ScannedOverInternet = false);

/// <param name="Certainty">0–100 – match certainty for CVEs, rule confidence for configuration findings.</param>
/// <param name="CertaintyText">Why that certainty (e.g. "wymaga weryfikacji – pakiet dystrybucji").</param>
public sealed record PathIssue(string Title, double Score, int? Port, string? CveId, int Certainty, string CertaintyText, bool KnownExploited, bool IsUpnp = false);

/// <summary>
/// Builds exposure paths from scan data: an attacker on the local network (the only vantage point the scans tested)
/// reaches an open service, the service has a weakness, and the weakness could lead to an impact that depends on the
/// device's role. Internet entry is shown only for public addresses or UPnP on a router, and then with low confidence.
/// Each step carries its justification and confidence; the path confidence is the product of the evidence steps.
/// </summary>
public static class AttackPathEngine
{
    public const double MinimumIssueScore = 35;
    public const int ImpactConfidence = 40;

    public static IReadOnlyList<AttackPath> Build(IReadOnlyList<PathAsset> assets, int take = 12)
    {
        var paths = new List<AttackPath>();
        foreach (var asset in assets)
        {
            foreach (var issue in asset.Issues.Where(i => i.Score >= MinimumIssueScore))
            {
                // A public host scanned over the Internet (Attack Surface) is not in any local network.
                if (!asset.ScannedOverInternet) paths.Add(LocalPath(asset, issue));
                if (InternetPath(asset, issue) is { } internet) paths.Add(internet);
            }
        }

        return paths.OrderByDescending(p => p.Priority).ThenByDescending(p => p.Confidence).Take(take).ToList();
    }

    private static AttackPath LocalPath(PathAsset asset, PathIssue issue)
    {
        var steps = new List<PathStep>
        {
            new(PathStepKind.Entry, $"Urządzenie w sieci lokalnej {asset.Network}",
                "Założenie: atakujący ma już dostęp do tej sieci (np. zainfekowany komputer, gość w Wi‑Fi, niezaufane urządzenie IoT). Skany WELES były wykonywane właśnie z sieci lokalnej.", null),
            Access(asset, issue),
            Weakness(asset, issue),
            Impact(asset, issue)
        };
        return Path($"local:{asset.AssetId}:{issue.Port}:{issue.CveId ?? issue.Title}", $"Sieć lokalna → {Label(asset)} → {issue.Title}", asset, issue, steps, 1.0);
    }

    private static AttackPath? InternetPath(PathAsset asset, PathIssue issue)
    {
        PathStep? exposure = null;
        var observed = asset.ScannedOverInternet;
        if (observed)
        {
            exposure = issue.Port is { } port
                ? new PathStep(PathStepKind.Access, $"Port {port} na {Label(asset)} jest otwarty",
                    $"Połączenie przez Internet nawiązane w skanie #{asset.ScanId} – usługa jest osiągalna z Internetu. Osiągalność nie oznacza możliwości przejęcia.", 95, asset.AssetId, port)
                : new PathStep(PathStepKind.Access, $"{Label(asset)} jest osiągalne z Internetu",
                    $"Host odpowiedział przez Internet w skanie #{asset.ScanId}.", 90, asset.AssetId);
        }
        else if (asset.HasPublicAddress)
        {
            exposure = new PathStep(PathStepKind.Access, $"{asset.Name} ma adres publiczny {asset.Ip}",
                "Adres publiczny może być osiągalny z Internetu, ale WELES nie sprawdzał tego z zewnątrz (zapora operatora lub routera może blokować ruch).", 50, asset.AssetId);
        }
        else if (asset.IsGateway && issue.IsUpnp)
        {
            exposure = new PathStep(PathStepKind.Access, $"UPnP na routerze {asset.Name}",
                "Programy w sieci mogą przez UPnP otworzyć porty routera na zewnątrz; WELES nie sprawdzał, czy jakieś przekierowania istnieją.", 20, asset.AssetId, issue.Port);
        }

        if (exposure is null) return null;
        var steps = new List<PathStep>
        {
            new(PathStepKind.Entry, "Internet", observed
                ? "Założenie: atakujący w Internecie – tak jak WELES podczas skanu aktywnego tego hosta."
                : "Założenie: atakujący w Internecie. Dostępność z Internetu nie była badana – ten krok jest najmniej pewny.", null),
            exposure,
            Weakness(asset, issue),
            Impact(asset, issue)
        };
        // Unverified reachability lowers the priority; reachability observed over the Internet does not.
        return Path($"internet:{asset.AssetId}:{issue.Port}:{issue.CveId ?? issue.Title}", $"Internet → {Label(asset)} → {issue.Title}", asset, issue, steps, observed ? 1.0 : 0.8);
    }

    private static PathStep Access(PathAsset asset, PathIssue issue) => issue.Port is { } port
        ? new PathStep(PathStepKind.Access, $"Port {port} na {Label(asset)} jest otwarty",
            $"Ta sama sieć lokalna co punkt startowy; port otwarty w skanie #{asset.ScanId} (połączenie TCP nawiązane). Osiągalność nie oznacza możliwości przejęcia.", 95, asset.AssetId, port)
        : new PathStep(PathStepKind.Access, $"{Label(asset)} jest osiągalne w sieci",
            $"Urządzenie odpowiedziało w skanie #{asset.ScanId}; problem dotyczy oprogramowania urządzenia, nie konkretnego portu.", 90, asset.AssetId);

    private static PathStep Weakness(PathAsset asset, PathIssue issue) =>
        new(PathStepKind.Weakness, issue.Title,
            $"{issue.CertaintyText}{(issue.KnownExploited ? "; CVE w katalogu CISA KEV – znane wykorzystanie w atakach" : "")}. WELES nie próbował tego wykorzystać.",
            issue.Certainty, asset.AssetId, issue.Port, issue.CveId);

    private static PathStep Impact(PathAsset asset, PathIssue issue)
    {
        var what = asset.IsGateway || asset.Type == AssetType.Router
            ? $"przejęcie routera – wgląd w ruch i wpływ na wszystkie {asset.DevicesOnNetwork} urządzenia w tej sieci"
            : asset.Type is AssetType.Server or AssetType.Nas
                ? "dostęp do danych i usług serwera, punkt wyjścia do dalszych urządzeń"
                : asset.Type is AssetType.IpCamera or AssetType.IoTDevice
                    ? "przejęcie urządzenia IoT – podsłuch lub przyczółek w sieci"
                    : "przejęcie urządzenia lub jego danych, punkt wyjścia do dalszych urządzeń";
        var critical = asset.Criticality >= AssetCriticality.High ? $" Urządzenie oznaczone jako {(asset.Criticality == AssetCriticality.Critical ? "krytyczne" : "o wysokiej krytyczności")}." : "";
        return new PathStep(PathStepKind.Impact, $"Możliwy skutek: {what}",
            $"Hipoteza oparta na roli urządzenia ({asset.Type}) – nie potwierdzono, że atak jest wykonalny.{critical}", ImpactConfidence, asset.AssetId);
    }

    /// <summary>"Raspberry Pi (192.168.0.103)" – the address is added only when the name does not contain it already.</summary>
    private static string Label(PathAsset asset) => asset.Ip is null || asset.Name.Contains(asset.Ip, StringComparison.Ordinal) ? asset.Name : $"{asset.Name} ({asset.Ip})";

    private static AttackPath Path(string key, string title, PathAsset asset, PathIssue issue, List<PathStep> steps, double factor)
    {
        // Path confidence: the evidence steps multiplied (the starting assumption and the hypothetical impact excluded).
        var confidence = steps.Where(s => s.Kind is PathStepKind.Access or PathStepKind.Weakness && s.Confidence is not null)
            .Aggregate(1.0, (acc, s) => acc * s.Confidence!.Value / 100.0);
        var criticality = RiskEngine.CriticalityMultiplier(asset.Criticality);
        var role = asset.IsGateway || asset.Type == AssetType.Router ? 8 : asset.Type is AssetType.Server or AssetType.Nas ? 5 : 0;
        var priority = Math.Round(Math.Clamp((issue.Score * criticality + role) * factor, 0, 100), 1);
        return new AttackPath(key, title, priority, RiskEngine.LevelOf(priority), (int)Math.Round(confidence * 100), steps, asset.AssetId);
    }
}
