using System.Text.Json;
using Weles.Core.Entities;

namespace Weles.App.Services;

/// <summary>Human-readable (Polish) presentation of service identification data, shared by scan and asset views.</summary>
public static class ServiceDetails
{
    public static Dictionary<string, string> Extra(DiscoveredService? svc)
    {
        if (string.IsNullOrEmpty(svc?.ExtraInfoJson)) return [];
        try { return JsonSerializer.Deserialize<Dictionary<string, string>>(svc.ExtraInfoJson) ?? []; }
        catch (JsonException) { return []; }
    }

    public sealed record Announcement(string Type, string Instance, int? Port);

    public static List<Announcement> Announced(DiscoveredHost h)
    {
        if (string.IsNullOrEmpty(h.AnnouncedServicesJson)) return [];
        try { return JsonSerializer.Deserialize<List<Announcement>>(h.AnnouncedServicesJson) ?? []; }
        catch (JsonException) { return []; }
    }

    public static string MethodLabel(string? method) => method is not null && method.EndsWith("+mdns", StringComparison.Ordinal)
        ? MethodLabel(method[..^5]) + " + ogłoszenie mDNS"
        : method switch
    {
        "adb-handshake" => "powitanie ADB (bez autoryzacji)",
        "banner" => "baner usługi",
        "banner-unrecognized" => "baner (nierozpoznany)",
        "http-request" => "żądanie HTTP",
        "http-banner" => "odpowiedź HTTP wysłana po połączeniu",
        "https-request" => "żądanie HTTPS",
        "tls-handshake" => "uzgadnianie TLS",
        "mysql-handshake" => "powitanie MySQL",
        "redis-ping" => "Redis PING",
        "postgres-sslrequest" => "PostgreSQL SSLRequest",
        "rdp-negotiation" => "negocjacja RDP",
        "dns-version-query" => "zapytanie DNS (version.bind)",
        "port-hint" => "tylko numer portu",
        null => "—",
        _ => method
    };

    public static IEnumerable<(string Text, bool Warn)> Details(Dictionary<string, string> x, DiscoveredService? svc)
    {
        if (x.TryGetValue("http.title", out var title)) yield return ($"Tytuł: {title}", false);
        if (x.TryGetValue("http.panel", out var panel))
        {
            // Admin/DevOps panels and login pages are exposure; a device's own UI or a print server is information.
            var requiresAuth = x.ContainsKey("http.requiresAuth");
            var exposed = !requiresAuth && x.GetValueOrDefault("http.panelCategory") is "admin-panel" or "devops" or "login-page";
            yield return (requiresAuth ? $"Panel: {panel} (wymaga logowania)"
                : exposed ? $"Panel: {panel} (strona startowa dostępna bez logowania)" : $"Interfejs WWW: {panel}", exposed);
        }
        if (x.TryGetValue("http.status", out var status)) yield return ($"HTTP {status}" + (x.TryGetValue("http.location", out var loc) ? $" → {loc}" : ""), false);
        if (x.ContainsKey("http.redirectsToHttps")) yield return ("Przekierowanie na HTTPS", false);
        if (x.TryGetValue("http.poweredBy", out var powered)) yield return ($"X-Powered-By: {powered}", true);
        if (x.TryGetValue("device.model", out var deviceModel)) yield return ($"Model urządzenia: {deviceModel}" + (x.TryGetValue("device.hardwareVersion", out var hw) ? $" (wersja sprzętu {hw})" : ""), false);
        if (x.TryGetValue("http.auth", out var auth)) yield return ($"Wymaga uwierzytelnienia: {auth}", false);
        if (x.ContainsKey("http.basicOverHttp")) yield return ("Logowanie HTTP Basic bez szyfrowania – hasło przesyłane jawnie w sieci", true);
        if (x.TryGetValue("http.missingHeaders", out var missing)) yield return ($"Brak nagłówków: {missing.Replace(",", ", ")}", true);
        if (x.TryGetValue("tls.protocol", out var proto)) yield return ($"TLS: {proto}" + (x.TryGetValue("tls.cipher", out var c) ? $" · {c}" : ""), false);
        if (x.TryGetValue("tls.legacy", out _)) yield return ("Akceptuje przestarzałe TLS 1.0/1.1", true);
        if (x.TryGetValue("tls.validation", out var validation)) yield return ($"Certyfikat nie przechodzi weryfikacji: {validation}", true);
        if (svc?.Certificates.FirstOrDefault() is { } cert)
        {
            var days = (cert.NotAfter - DateTime.UtcNow).TotalDays;
            yield return ($"Certyfikat: {cert.Subject} · wystawca {cert.Issuer}", false);
            yield return (days < 0 ? $"Certyfikat WYGASŁ {cert.NotAfter.ToLocalTime():d}" : $"Ważny do {cert.NotAfter.ToLocalTime():d} ({days:0} dni)", days < 30);
            if (cert.IsSelfSigned) yield return ("Certyfikat samopodpisany", true);
            if (cert.HostnameMatches == false) yield return ("Nazwa w certyfikacie nie pasuje do nazwy hosta", true);
            if (cert.KeySize is { } size && cert.KeyAlgorithm?.Contains("RSA") == true && size < 2048) yield return ($"Słaby klucz RSA {size} bit", true);
        }

        if (x.TryGetValue("redis.auth", out var redisAuth)) yield return (redisAuth == "none" ? "Redis bez uwierzytelniania" : "Redis wymaga uwierzytelnienia", redisAuth == "none");
        if (x.TryGetValue("rdp.security", out var rdp)) yield return ($"Zabezpieczenie RDP: {rdp}", !rdp.StartsWith("NLA", StringComparison.Ordinal));
        if (x.TryGetValue("postgresql.ssl", out var pgSsl)) yield return (pgSsl == "supported" ? "PostgreSQL obsługuje SSL" : "PostgreSQL bez obsługi SSL", pgSsl != "supported");
        if (x.TryGetValue("mysql.access", out _)) yield return ("Serwer odrzuca połączenia z tego hosta", false);
        if (x.TryGetValue("adb.auth", out var adbAuth))
        {
            yield return (adbAuth == "none"
                ? "ADB przez sieć BEZ autoryzacji – pełny dostęp do urządzenia dla każdego w sieci"
                : "ADB przez sieć włączone (wymaga zatwierdzenia na urządzeniu) – wyłącz, jeśli nieużywane", true);
            if (x.TryGetValue("adb.model", out var model)) yield return ($"Model: {model}", false);
        }

        if (x.TryGetValue("mdns.service", out var mdnsService))
            yield return ($"Ogłaszane przez mDNS: {mdnsService}" + (x.TryGetValue("mdns.instance", out var inst) ? $" („{inst}”)" : ""), x.ContainsKey("mdns.risky"));
        if (x.TryGetValue("dns.rcode", out var rcode)) yield return ($"DNS potwierdzony (odpowiedź {rcode})", false);
        if (x.TryGetValue("dns.version", out var dnsVersion)) yield return ($"Ujawniona wersja: {dnsVersion}", true);
        if (x.ContainsKey("dns.versionNote")) yield return ("Wersja może należeć do serwera nadrzędnego (przekazywanie zapytań) – wymaga weryfikacji", false);
        if (x.ContainsKey("http.upnp")) yield return ("Usługa UPnP dostępna w sieci", true);
        if (x.TryGetValue("http.initialStatus", out var initial)) yield return ($"Strona po przekierowaniu (pierwsza odpowiedź HTTP {initial})", false);
        if (x.TryGetValue("rfb.version", out var rfb)) yield return ($"Protokół RFB {rfb}", false);
        if (svc?.ServiceName == "telnet") yield return ("Telnet przesyła dane bez szyfrowania", true);
        if (svc?.DetectionMethod == "port-hint") yield return ("Usługa nie odpowiedziała na sondy – nazwa wynika tylko z numeru portu", false);
    }
}
