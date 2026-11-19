using Weles.Core.Enums;
using Weles.App.Localization;
using Weles.Infrastructure.Scanning;

namespace Weles.App.Services;

/// <summary>Display names for domain enums (Polish source texts, translated through <see cref="L"/>).</summary>
public static class Labels
{
    public static string Of(ScanStatus status) => status switch
    {
        ScanStatus.Pending => L.T("Oczekuje"),
        ScanStatus.Running => L.T("W toku"),
        ScanStatus.Completed => L.T("Zakończony"),
        ScanStatus.Cancelled => L.T("Zatrzymany"),
        ScanStatus.Failed => L.T("Błąd"),
        _ => status.ToString()
    };

    public static string Tone(ScanStatus status) => status switch
    {
        ScanStatus.Completed => "ok",
        ScanStatus.Running or ScanStatus.Pending => "info",
        ScanStatus.Cancelled => "warn",
        ScanStatus.Failed => "bad",
        _ => "muted"
    };

    public static string Of(ScanPhase phase) => phase switch
    {
        ScanPhase.Queued => L.T("W kolejce"),
        ScanPhase.ResolvingScope => L.T("Rozwiązywanie zakresu"),
        ScanPhase.HostDiscovery => L.T("Wykrywanie hostów"),
        ScanPhase.PortScan => L.T("Porty i usługi"),
        ScanPhase.Finishing => L.T("Zapisywanie wyników"),
        ScanPhase.Finished => L.T("Zakończono"),
        _ => phase.ToString()
    };

    public static string Of(AssetType type) => type switch
    {
        AssetType.Unknown => L.T("Nieznany"),
        AssetType.WindowsHost => L.T("Komputer Windows"),
        AssetType.LinuxHost => L.T("Komputer Linux"),
        AssetType.Server => L.T("Serwer"),
        AssetType.Router => L.T("Router"),
        AssetType.Switch => L.T("Switch"),
        AssetType.Printer => L.T("Drukarka"),
        AssetType.IpCamera => L.T("Kamera IP"),
        AssetType.IoTDevice => L.T("Urządzenie IoT"),
        AssetType.VirtualMachine => L.T("Maszyna wirtualna"),
        AssetType.Nas => L.T("NAS"),
        AssetType.NetworkDevice => L.T("Urządzenie sieciowe"),
        AssetType.MobileDevice => L.T("Urządzenie mobilne"),
        _ => type.ToString()
    };

    /// <summary>Polish plural: 1 urządzenie, 2–4 urządzenia, 5+ urządzeń (12–14 urządzeń).</summary>
    public static string Devices(int n) =>
        L.IsEnglish ? (n == 1 ? "device" : "devices")
        : n == 1 ? "urządzenie" : n % 10 is >= 2 and <= 4 && n % 100 is not (>= 12 and <= 14) ? "urządzenia" : "urządzeń";

    public static string Of(AssetStatus status) => status switch
    {
        AssetStatus.New => L.T("Nowe"),
        AssetStatus.Active => L.T("Aktywne"),
        AssetStatus.Missing => L.T("Nieobecne"),
        AssetStatus.NotCovered => L.T("Poza ostatnimi skanami"),
        AssetStatus.Unknown => L.T("Nieznane"),
        _ => status.ToString()
    };

    public static string Tone(AssetStatus status) => status switch
    {
        AssetStatus.New => "info",
        AssetStatus.Active => "ok",
        AssetStatus.Missing => "warn",
        _ => "muted"
    };

    public static string Describe(AssetStatus status) => status switch
    {
        AssetStatus.New => L.T("Wykryte po raz pierwszy w ostatnim skanie obejmującym jego adres"),
        AssetStatus.Active => L.T("Wykryte w ostatnim skanie obejmującym jego adres (w tym nowe)"),
        AssetStatus.Missing => L.T("Ostatni skan jego sieci obejmujący jego adres nie znalazł urządzenia (skany innych sieci z tym samym zakresem adresów się nie liczą)"),
        AssetStatus.NotCovered => L.T("Żaden zakończony skan nie obejmował ostatnio jego adresu"),
        AssetStatus.Unknown => L.T("Ostatnio sprawdzone w swojej sieci, ale potem skanowano inną sieć – obecny stan nie jest znany. Zaktualizuje się po skanie jego sieci"),
        _ => ""
    };

    public static string Of(VulnerabilityMatchStatus status) => status switch
    {
        VulnerabilityMatchStatus.Confirmed => L.T("Potwierdzone"),
        VulnerabilityMatchStatus.Probable => L.T("Prawdopodobne"),
        VulnerabilityMatchStatus.NeedsVerification => L.T("Wymaga weryfikacji"),
        VulnerabilityMatchStatus.InsufficientData => L.T("Brak wystarczających danych"),
        _ => status.ToString()
    };

    public static string Tone(VulnerabilityMatchStatus status) => status switch
    {
        VulnerabilityMatchStatus.Confirmed => "bad",
        VulnerabilityMatchStatus.Probable => "warn",
        VulnerabilityMatchStatus.NeedsVerification => "info",
        _ => "muted"
    };

    public static string Describe(VulnerabilityMatchStatus status) => status switch
    {
        VulnerabilityMatchStatus.Confirmed => L.T("Producent, produkt i dokładna wersja z pewnego rozpoznania (baner/protokół) mieszczą się w zakresie podanym przez NVD"),
        VulnerabilityMatchStatus.Probable => L.T("Wersja w zakresie, ale rozpoznanie jest mniej pewne albo NVD wymaga dodatkowego warunku (np. systemu), którego skan nie potwierdza"),
        VulnerabilityMatchStatus.NeedsVerification => L.T("Wersja pasuje, ale mogą istnieć poprawki dystrybucji (backport), wersja jest niedokładna lub pewność rozpoznania jest niska (< 70%)"),
        VulnerabilityMatchStatus.InsufficientData => L.T("Model urządzenia jest wymieniony w NVD, ale skan nie zna wersji oprogramowania, albo NVD nie podaje zakresu podatnych wersji – trzeba to sprawdzić ręcznie"),
        _ => ""
    };

    public static string Of(FindingStatus status) => status switch
    {
        FindingStatus.Open => L.T("Otwarte"),
        FindingStatus.Resolved => L.T("Rozwiązane"),
        FindingStatus.Accepted => L.T("Zaakceptowane"),
        _ => status.ToString()
    };

    public static string Tone(FindingStatus status) => status switch
    {
        FindingStatus.Open => "warn",
        FindingStatus.Resolved => "ok",
        _ => "muted"
    };

    public static string Of(RiskLevel level) => level switch
    {
        RiskLevel.Critical => L.T("Krytyczna"),
        RiskLevel.High => L.T("Wysoka"),
        RiskLevel.Medium => L.T("Średnia"),
        RiskLevel.Low => L.T("Niska"),
        RiskLevel.Informational => L.T("Informacyjna"),
        _ => level.ToString()
    };

    public static string Tone(RiskLevel? level) => level switch
    {
        RiskLevel.Critical or RiskLevel.High => "bad",
        RiskLevel.Medium => "warn",
        RiskLevel.Low => "info",
        _ => "muted"
    };

    /// <summary>EPSS as a percentage with sensible precision: 0.00043 → "0,04%", 0.94432 → "94,4%".</summary>
    public static string Epss(double? score) => score switch
    {
        null => "—",
        < 0.001 => (score.Value * 100).ToString("0.00") + "%",
        < 0.1 => (score.Value * 100).ToString("0.0#") + "%",
        _ => (score.Value * 100).ToString("0.0") + "%"
    };

    public static string Of(AssetCriticality criticality) => criticality switch
    {
        AssetCriticality.Low => L.T("Niska"),
        AssetCriticality.Medium => L.T("Średnia"),
        AssetCriticality.High => L.T("Wysoka"),
        AssetCriticality.Critical => L.T("Krytyczna"),
        _ => criticality.ToString()
    };

    public static string Tone(AssetChangeKind kind) => kind switch
    {
        AssetChangeKind.PortOpened or AssetChangeKind.ServiceChanged or AssetChangeKind.MacChanged => "warn",
        AssetChangeKind.PortClosed => "ok",
        _ => "info"
    };

    public static string Of(DiscoveryMethod methods)
    {
        var parts = new List<string>();
        if (methods.HasFlag(DiscoveryMethod.Icmp)) parts.Add("ICMP");
        if (methods.HasFlag(DiscoveryMethod.TcpConnect)) parts.Add("TCP");
        if (methods.HasFlag(DiscoveryMethod.Arp)) parts.Add("ARP");
        if (methods.HasFlag(DiscoveryMethod.Dns)) parts.Add("DNS");
        if (methods.HasFlag(DiscoveryMethod.Mdns)) parts.Add("mDNS");
        if (methods.HasFlag(DiscoveryMethod.Agent)) parts.Add("Agent");
        return parts.Count == 0 ? "—" : string.Join(" · ", parts);
    }

    public static string Duration(DateTime? start, DateTime? end)
    {
        if (start is null) return "—";
        var span = (end ?? DateTime.UtcNow) - start.Value;
        return span.TotalHours >= 1 ? $"{(int)span.TotalHours} h {span.Minutes} min" : span.TotalMinutes >= 1 ? $"{(int)span.TotalMinutes} min {span.Seconds} s" : $"{Math.Max(0, span.Seconds)} s";
    }

    public static string Local(DateTime? utc) => utc?.ToLocalTime().ToString(L.IsEnglish ? "dd/MM/yyyy HH:mm" : "dd.MM.yyyy HH:mm") ?? "—";
}
