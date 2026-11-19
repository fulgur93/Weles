using Weles.Core.Enums;
using Weles.Infrastructure.Scanning;

namespace Weles.App.Services;

/// <summary>Polish display names for domain enums.</summary>
public static class Labels
{
    public static string Of(ScanStatus status) => status switch
    {
        ScanStatus.Pending => "Oczekuje",
        ScanStatus.Running => "W toku",
        ScanStatus.Completed => "Zakończony",
        ScanStatus.Cancelled => "Zatrzymany",
        ScanStatus.Failed => "Błąd",
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
        ScanPhase.Queued => "W kolejce",
        ScanPhase.ResolvingScope => "Rozwiązywanie zakresu",
        ScanPhase.HostDiscovery => "Wykrywanie hostów",
        ScanPhase.PortScan => "Porty i usługi",
        ScanPhase.Finishing => "Zapisywanie wyników",
        ScanPhase.Finished => "Zakończono",
        _ => phase.ToString()
    };

    public static string Of(AssetType type) => type switch
    {
        AssetType.Unknown => "Nieznany",
        AssetType.WindowsHost => "Komputer Windows",
        AssetType.LinuxHost => "Komputer Linux",
        AssetType.Server => "Serwer",
        AssetType.Router => "Router",
        AssetType.Switch => "Switch",
        AssetType.Printer => "Drukarka",
        AssetType.IpCamera => "Kamera IP",
        AssetType.IoTDevice => "Urządzenie IoT",
        AssetType.VirtualMachine => "Maszyna wirtualna",
        AssetType.Nas => "NAS",
        AssetType.NetworkDevice => "Urządzenie sieciowe",
        AssetType.MobileDevice => "Urządzenie mobilne",
        _ => type.ToString()
    };

    /// <summary>Polish plural: 1 urządzenie, 2–4 urządzenia, 5+ urządzeń (12–14 urządzeń).</summary>
    public static string Devices(int n) =>
        n == 1 ? "urządzenie" : n % 10 is >= 2 and <= 4 && n % 100 is not (>= 12 and <= 14) ? "urządzenia" : "urządzeń";

    public static string Of(AssetStatus status) => status switch
    {
        AssetStatus.New => "Nowe",
        AssetStatus.Active => "Aktywne",
        AssetStatus.Missing => "Nieobecne",
        AssetStatus.NotCovered => "Poza ostatnimi skanami",
        AssetStatus.Unknown => "Nieznane",
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
        AssetStatus.New => "Wykryte po raz pierwszy w ostatnim skanie obejmującym jego adres",
        AssetStatus.Active => "Wykryte w ostatnim skanie obejmującym jego adres (w tym nowe)",
        AssetStatus.Missing => "Ostatni skan jego sieci obejmujący jego adres nie znalazł urządzenia (skany innych sieci z tym samym zakresem adresów się nie liczą)",
        AssetStatus.NotCovered => "Żaden zakończony skan nie obejmował ostatnio jego adresu",
        AssetStatus.Unknown => "Ostatnio sprawdzone w swojej sieci, ale potem skanowano inną sieć – obecny stan nie jest znany. Zaktualizuje się po skanie jego sieci",
        _ => ""
    };

    public static string Of(AssetCriticality criticality) => criticality switch
    {
        AssetCriticality.Low => "Niska",
        AssetCriticality.Medium => "Średnia",
        AssetCriticality.High => "Wysoka",
        AssetCriticality.Critical => "Krytyczna",
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

    public static string Local(DateTime? utc) => utc?.ToLocalTime().ToString("dd.MM.yyyy HH:mm") ?? "—";
}
