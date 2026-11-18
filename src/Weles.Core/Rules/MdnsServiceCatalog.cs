using Weles.Core.Enums;

namespace Weles.Core.Rules;

/// <summary>Meaning of DNS-SD service types announced over mDNS.</summary>
public static class MdnsServiceCatalog
{
    public sealed record Entry(string Label, string ServiceName, AssetType? Device, string? Os, bool IsRisky);

    private static readonly Dictionary<string, Entry> Entries = new(StringComparer.OrdinalIgnoreCase)
    {
        ["_adb-tls-connect._tcp"] = new("Debugowanie bezprzewodowe Android (ADB)", "adb-tls", AssetType.MobileDevice, "Android", true),
        ["_adb-tls-pairing._tcp"] = new("Parowanie debugowania bezprzewodowego Android", "adb-pairing", AssetType.MobileDevice, "Android", true),
        ["_adb._tcp"] = new("Android Debug Bridge", "adb", null, "Android", true),
        ["_googlecast._tcp"] = new("Google Cast", "googlecast", AssetType.IoTDevice, null, false),
        ["_androidtvremote2._tcp"] = new("Pilot Android TV", "androidtv-remote", AssetType.IoTDevice, "Android", false),
        ["_ipp._tcp"] = new("Drukarka IPP", "ipp", AssetType.Printer, null, false),
        ["_ipps._tcp"] = new("Drukarka IPP (TLS)", "ipps", AssetType.Printer, null, false),
        ["_printer._tcp"] = new("Drukarka LPD", "printer", AssetType.Printer, null, false),
        ["_pdl-datastream._tcp"] = new("Drukarka (RAW 9100)", "jetdirect", AssetType.Printer, null, false),
        ["_scanner._tcp"] = new("Skaner", "scanner", AssetType.Printer, null, false),
        ["_uscan._tcp"] = new("Skaner eSCL", "escl", AssetType.Printer, null, false),
        ["_airplay._tcp"] = new("AirPlay", "airplay", null, null, false),
        ["_raop._tcp"] = new("AirPlay audio", "raop", null, null, false),
        ["_companion-link._tcp"] = new("Apple Companion Link", "companion-link", AssetType.MobileDevice, "iOS/iPadOS", false),
        ["_apple-mobdev2._tcp"] = new("Synchronizacja urządzenia Apple", "apple-mobdev", AssetType.MobileDevice, "iOS/iPadOS", false),
        ["_hap._tcp"] = new("Apple HomeKit", "homekit", AssetType.IoTDevice, null, false),
        ["_spotify-connect._tcp"] = new("Spotify Connect", "spotify-connect", null, null, false),
        ["_smb._tcp"] = new("Udział SMB", "smb", null, null, false),
        ["_afpovertcp._tcp"] = new("Udział AFP", "afp", null, "macOS", false),
        ["_ssh._tcp"] = new("SSH", "ssh", null, null, false),
        ["_sftp-ssh._tcp"] = new("SFTP", "sftp", null, null, false),
        ["_rfb._tcp"] = new("Pulpit zdalny VNC", "vnc", null, null, true),
        ["_http._tcp"] = new("Strona WWW", "http", null, null, false),
        ["_https._tcp"] = new("Strona WWW (TLS)", "https", null, null, false),
        ["_workstation._tcp"] = new("Stacja robocza", "workstation", null, "Linux", false),
        ["_device-info._tcp"] = new("Informacje o urządzeniu", "device-info", null, null, false),
        ["_kdeconnect._udp"] = new("KDE Connect", "kdeconnect", null, null, false),
        ["_mqtt._tcp"] = new("Broker MQTT", "mqtt", AssetType.IoTDevice, null, false),
    };

    /// <summary>Types always asked for, even if a responder does not answer the service enumeration query.</summary>
    public static IReadOnlyCollection<string> InterestingTypes => Entries.Keys;

    public static Entry? Find(string serviceType) => Entries.GetValueOrDefault(Normalize(serviceType));

    /// <summary>"_ipp._tcp.local" → "_ipp._tcp"; instance names like "Printer._ipp._tcp.local" are not types.</summary>
    public static string Normalize(string name)
    {
        var n = name.TrimEnd('.');
        if (n.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) n = n[..^6];
        return n;
    }
}
