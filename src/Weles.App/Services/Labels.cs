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
        _ => type.ToString()
    };

    public static string Of(DiscoveryMethod methods)
    {
        var parts = new List<string>();
        if (methods.HasFlag(DiscoveryMethod.Icmp)) parts.Add("ICMP");
        if (methods.HasFlag(DiscoveryMethod.TcpConnect)) parts.Add("TCP");
        if (methods.HasFlag(DiscoveryMethod.Arp)) parts.Add("ARP");
        if (methods.HasFlag(DiscoveryMethod.Dns)) parts.Add("DNS");
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
