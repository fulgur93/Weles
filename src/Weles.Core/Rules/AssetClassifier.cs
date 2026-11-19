using Weles.Core.Enums;
using Weles.Core.Models;

namespace Weles.Core.Rules;

public sealed record HostEvidence(
    IReadOnlyCollection<int> OpenPorts,
    IReadOnlyCollection<ServiceIdentification> Services,
    string? Vendor,
    int? Ttl,
    bool IsGateway,
    string? Hostname,
    bool IsLocalMachine = false,
    bool HasRandomizedMac = false,
    IReadOnlyCollection<string>? MdnsServiceTypes = null);

public sealed record HostClassification(AssetType Type, string? OsFamily, int Confidence, IReadOnlyList<string> Reasons);

/// <summary>
/// Heuristic device classification. Every conclusion carries its reasons so the UI can explain it.
/// </summary>
public static class AssetClassifier
{
    public static HostClassification Classify(HostEvidence e)
    {
        var reasons = new List<string>();
        var ports = e.OpenPorts.ToHashSet();
        var vendor = e.Vendor ?? "";

        // --- Operating system ---
        string? os = null;
        var osHint = e.Services.Select(s => s.OsHint).FirstOrDefault(h => h is not null);
        if (e.IsLocalMachine)
        {
            os = OperatingSystem.IsWindows() ? "Windows" : OperatingSystem.IsMacOS() ? "macOS" : "Linux";
            reasons.Add($"Komputer, na którym działa WELES ({os})");
        }
        else if (MdnsOs(e) is { } mdnsOs)
        {
            os = mdnsOs.Os;
            reasons.Add($"Urządzenie ogłasza w sieci (mDNS): {mdnsOs.Label}");
        }
        else if (e.OpenPorts.Contains(62078))
        {
            os = "iOS/iPadOS";
            reasons.Add("Port synchronizacji iPhone/iPad (62078)");
        }
        else if (osHint is not null)
        {
            os = osHint.StartsWith("Linux", StringComparison.Ordinal) ? "Linux" : osHint;
            reasons.Add($"System {osHint} wskazany przez baner usługi");
        }
        else if (ports.Overlaps([135, 445, 3389, 5985]) && ports.Contains(135))
        {
            os = "Windows";
            reasons.Add("Otwarte porty typowe dla Windows (RPC 135, SMB 445, RDP 3389)");
        }
        else if (e.Ttl is { } ttl)
        {
            (os, var why) = ttl switch
            {
                > 128 => ("Network OS", $"TTL {ttl} (typowo urządzenia sieciowe)"),
                > 64 => ("Windows", $"TTL {ttl} (typowo Windows)"),
                > 0 => ("Linux/Unix", $"TTL {ttl} (typowo Linux/Unix)"),
                _ => (null, null)
            };
            if (why is not null) reasons.Add(why + " – niska pewność");
        }

        if (e.Services.Select(s => s.Extra.GetValueOrDefault("device.model")).FirstOrDefault(m => m is not null) is { } model)
        {
            reasons.Add($"Model zgłoszony przez urządzenie: {model}");
        }

        // --- Device type ---
        var deviceFromHttp = e.Services.Select(s => s.Extra.GetValueOrDefault("http.device")).FirstOrDefault(d => d is not null);
        AssetType type;
        int confidence;

        if (e.IsLocalMachine)
        {
            type = os == "Windows" ? AssetType.WindowsHost : AssetType.LinuxHost; confidence = 95;
            if (os == "macOS") type = AssetType.Unknown;
        }
        else if (os is "Android" or "iOS/iPadOS" && MdnsDevice(e) is not AssetType.IoTDevice && deviceFromHttp is null)
        {
            type = AssetType.MobileDevice; confidence = 75;
            if (e.Services.FirstOrDefault(s => s.Extra.ContainsKey("adb.model")) is { } adb) reasons.Add($"Model zgłoszony przez ADB: {adb.Extra["adb.model"]}");
        }
        else if (MdnsDevice(e) is { } mdnsDevice)
        {
            type = mdnsDevice; confidence = 80;
            reasons.Add($"Typ wynika z usług ogłaszanych przez mDNS: {string.Join(", ", (e.MdnsServiceTypes ?? []).Select(t => MdnsServiceCatalog.Find(t)?.Label ?? t).Distinct())}");
        }
        else if (IsVirtualMachineVendor(vendor))
        {
            type = AssetType.VirtualMachine; confidence = 80;
            reasons.Add($"Producent karty sieciowej: {vendor} (wirtualizacja)");
        }
        else if (deviceFromHttp is not null && Enum.TryParse<AssetType>(deviceFromHttp, out var httpType))
        {
            type = httpType; confidence = 80;
            var source = e.Services.First(s => s.Extra.GetValueOrDefault("http.device") == deviceFromHttp);
            reasons.Add(source.Extra.TryGetValue("http.panel", out var panelName) ? $"Interfejs WWW urządzenia: {panelName}" : "Nagłówek usługi UPnP wskazuje producenta urządzenia");
            if (e.IsGateway && type is AssetType.Router or AssetType.NetworkDevice)
            {
                confidence = 90;
                reasons.Add("Brama domyślna segmentu sieci");
            }
        }
        else if (ports.Overlaps([9100, 515, 631]) && (ports.Contains(9100) || ContainsAny(vendor, "HP", "Hewlett", "Brother", "Canon", "Epson", "Xerox", "Kyocera", "Lexmark", "Ricoh")))
        {
            type = AssetType.Printer; confidence = 75;
            reasons.Add("Porty drukowania (9100 JetDirect / 515 LPD / 631 IPP)");
        }
        else if (ports.Contains(554) || ContainsAny(vendor, "Hikvision", "Dahua", "Axis", "Hanwha", "Uniview", "Reolink"))
        {
            type = AssetType.IpCamera; confidence = ports.Contains(554) && vendor.Length > 0 ? 80 : 60;
            reasons.Add(ports.Contains(554) ? "Strumień RTSP (port 554)" : $"Producent: {vendor}");
        }
        else if (e.IsGateway)
        {
            type = AssetType.Router; confidence = 85;
            reasons.Add("Brama domyślna segmentu sieci");
        }
        else if (ContainsAny(vendor, "Synology", "QNAP", "Western Digital", "Buffalo"))
        {
            type = AssetType.Nas; confidence = 75;
            reasons.Add($"Producent: {vendor}");
        }
        else if (ContainsAny(vendor, NetworkVendors) || os == "Network OS")
        {
            type = ports.Overlaps([22, 23, 80, 443]) ? AssetType.NetworkDevice : AssetType.Switch;
            confidence = 60;
            reasons.Add(vendor.Length > 0 ? $"Producent sprzętu sieciowego: {vendor}" : "TTL charakterystyczny dla urządzeń sieciowych");
        }
        else if (ports.Contains(1883) || ContainsAny(vendor, IoTVendors))
        {
            type = AssetType.IoTDevice; confidence = 65;
            reasons.Add(ports.Contains(1883) ? "Broker/urządzenie MQTT (1883)" : $"Producent urządzeń IoT/multimedialnych: {vendor}");
        }
        else if (e.Services.Any(s => s.Extra.ContainsKey("http.upnp")) && os is null)
        {
            type = AssetType.IoTDevice; confidence = 45;
            reasons.Add("Usługa UPnP (typowo urządzenie multimedialne lub IoT) – niska pewność");
        }
        else if (os == "Windows")
        {
            type = ports.Overlaps([53, 88, 389, 1433, 3268]) ? AssetType.Server : AssetType.WindowsHost;
            confidence = 65;
            if (type == AssetType.Server) reasons.Add("Usługi serwerowe Windows (DNS/Kerberos/LDAP/MSSQL)");
        }
        else if (os is "Linux" or "Linux/Unix" or "FreeBSD")
        {
            type = ports.Overlaps([25, 53, 80, 443, 3306, 5432, 6379, 8080, 27017]) ? AssetType.Server : AssetType.LinuxHost;
            confidence = 60;
            if (type == AssetType.Server) reasons.Add("Usługi serwerowe (WWW/baza danych/poczta/DNS)");
        }
        else
        {
            type = AssetType.Unknown; confidence = 0;
            reasons.Add("Za mało danych do określenia typu urządzenia");
        }

        if (e.HasRandomizedMac && type == AssetType.Unknown)
        {
            reasons.Add("Losowy adres MAC – zwykle telefon, tablet lub laptop z ochroną prywatności");
        }

        return new HostClassification(type, os, confidence, reasons);
    }

    private static (string Os, string Label)? MdnsOs(HostEvidence e)
    {
        foreach (var type in e.MdnsServiceTypes ?? [])
        {
            if (MdnsServiceCatalog.Find(type) is { Os: { } os } entry && os is "Android" or "iOS/iPadOS" or "macOS") return (os, entry.Label);
        }

        return null;
    }

    private static AssetType? MdnsDevice(HostEvidence e) =>
        (e.MdnsServiceTypes ?? []).Select(t => MdnsServiceCatalog.Find(t)?.Device).FirstOrDefault(d => d is not null);

    private static readonly string[] NetworkVendors =
    [
        "Cisco", "Juniper", "MikroTik", "Routerboard", "Ubiquiti", "Aruba", "Netgear", "TP-Link", "Zyxel", "Fortinet", "Tenda", "D-Link",
        "Huawei", "ZTE", "Sagemcom", "Technicolor", "AVM", "Linksys", "Mercusys", "Edimax", "Netis", "Draytek", "Arcadyan", "Askey"
    ];

    private static readonly string[] IoTVendors =
    [
        "Espressif", "Tuya", "Shelly", "Sonoff", "Philips Lighting", "Signify", "Nest", "Advanced Digital Broadcast", "Frontier Silicon",
        "Roku", "Sonos", "Humax", "Vestel", "TechniSat", "Amazon Technologies", "Ring LLC", "Ecobee", "Wyze"
    ];

    public static bool IsVirtualMachineVendor(string vendor) =>
        ContainsAny(vendor, "VMware", "Oracle VirtualBox", "PCS Systemtechnik", "QEMU", "Xensource", "Parallels", "Microsoft Corporation Hyper-V")
        || vendor.Contains("Red Hat", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAny(string value, params string[] needles) =>
        needles.Any(n => value.Contains(n, StringComparison.OrdinalIgnoreCase));
}
