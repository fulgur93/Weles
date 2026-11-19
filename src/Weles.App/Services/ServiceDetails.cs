using System.Text.Json;
using Weles.Core.Entities;
using Weles.App.Localization;

namespace Weles.App.Services;

/// <summary>Human-readable presentation (translated through <see cref="L"/>) of service identification data, shared by scan and asset views.</summary>
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
        ? MethodLabel(method[..^5]) + L.T(" + ogłoszenie mDNS")
        : method switch
    {
        "adb-handshake" => L.T("powitanie ADB (bez autoryzacji)"),
        "banner" => L.T("baner usługi"),
        "banner-unrecognized" => "baner (nierozpoznany)",
        "http-request" => L.T("żądanie HTTP"),
        "http-banner" => L.T("odpowiedź HTTP wysłana po połączeniu"),
        "https-request" => L.T("żądanie HTTPS"),
        "tls-handshake" => "uzgadnianie TLS",
        "mysql-handshake" => "powitanie MySQL",
        "redis-ping" => L.T("Redis PING"),
        "postgres-sslrequest" => L.T("PostgreSQL SSLRequest"),
        "rdp-negotiation" => "negocjacja RDP",
        "dns-version-query" => L.T("zapytanie DNS (version.bind)"),
        "port-hint" => L.T("tylko numer portu"),
        null => "—",
        _ => method
    };

    public static IEnumerable<(string Text, bool Warn)> Details(Dictionary<string, string> x, DiscoveredService? svc)
    {
        if (x.TryGetValue("http.title", out var title)) yield return (L.F("Tytuł: {0}", title), false);
        if (x.TryGetValue("http.panel", out var panel))
        {
            // Admin/DevOps panels and login pages are exposure; a device's own UI or a print server is information.
            var requiresAuth = x.ContainsKey("http.requiresAuth");
            var exposed = !requiresAuth && x.GetValueOrDefault("http.panelCategory") is "admin-panel" or "devops" or "login-page";
            yield return (requiresAuth ? L.F("Panel: {0} (wymaga logowania)", L.Message(panel))
                : exposed ? L.F("Panel: {0} (strona startowa dostępna bez logowania)", L.Message(panel)) : L.F("Interfejs WWW: {0}", L.Message(panel)), exposed);
        }
        if (x.TryGetValue("http.status", out var status)) yield return ($"HTTP {status}" + (x.TryGetValue("http.location", out var loc) ? $" → {loc}" : ""), false);
        if (x.ContainsKey("http.redirectsToHttps")) yield return (L.T("Przekierowanie na HTTPS"), false);
        if (x.TryGetValue("http.poweredBy", out var powered)) yield return ($"X-Powered-By: {powered}", true);
        if (x.TryGetValue("device.model", out var deviceModel)) yield return (L.F("Model urządzenia: {0}", deviceModel) + (x.TryGetValue("device.hardwareVersion", out var hw) ? L.F(" (wersja sprzętu {0})", hw) : ""), false);
        if (x.TryGetValue("http.auth", out var auth)) yield return ($"Wymaga uwierzytelnienia: {auth}", false);
        if (x.ContainsKey("http.basicOverHttp")) yield return (L.T("Logowanie HTTP Basic bez szyfrowania – hasło przesyłane jawnie w sieci"), true);
        if (x.TryGetValue("http.missingHeaders", out var missing)) yield return (L.F("Brak nagłówków: {0}", missing.Replace(",", ", ")), true);
        if (x.TryGetValue("tls.protocol", out var proto)) yield return ($"TLS: {proto}" + (x.TryGetValue("tls.cipher", out var c) ? $" · {c}" : ""), false);
        if (x.TryGetValue("tls.legacy", out _)) yield return (L.T("Akceptuje przestarzałe TLS 1.0/1.1"), true);
        if (x.TryGetValue("tls.validation", out var validation)) yield return (L.F("Certyfikat nie przechodzi weryfikacji: {0}", validation), true);
        if (svc?.Certificates.FirstOrDefault() is { } cert)
        {
            var days = (cert.NotAfter - DateTime.UtcNow).TotalDays;
            yield return (L.F("Certyfikat: {0} · wystawca {1}", cert.Subject, cert.Issuer), false);
            yield return (days < 0 ? L.F("Certyfikat WYGASŁ {0:d}", cert.NotAfter.ToLocalTime()) : L.F("Ważny do {0:d} ({1:0} dni)", cert.NotAfter.ToLocalTime(), days), days < 30);
            if (cert.IsSelfSigned) yield return (L.T("Certyfikat samopodpisany"), true);
            if (cert.HostnameMatches == false) yield return (L.T("Nazwa w certyfikacie nie pasuje do nazwy hosta"), true);
            if (cert.KeySize is { } size && cert.KeyAlgorithm?.Contains("RSA") == true && size < 2048) yield return (L.F("Słaby klucz RSA {0} bit", size), true);
        }

        if (x.TryGetValue("redis.auth", out var redisAuth)) yield return (redisAuth == "none" ? L.T("Redis bez uwierzytelniania") : L.T("Redis wymaga uwierzytelnienia"), redisAuth == "none");
        if (x.TryGetValue("rdp.security", out var rdp)) yield return (L.F("Zabezpieczenie RDP: {0}", rdp), !rdp.StartsWith("NLA", StringComparison.Ordinal));
        if (x.TryGetValue("postgresql.ssl", out var pgSsl)) yield return (pgSsl == "supported" ? L.T("PostgreSQL obsługuje SSL") : L.T("PostgreSQL bez obsługi SSL"), pgSsl != "supported");
        if (x.TryGetValue("mysql.access", out _)) yield return (L.T("Serwer odrzuca połączenia z tego hosta"), false);
        if (x.TryGetValue("adb.auth", out var adbAuth))
        {
            yield return (adbAuth == "none"
                ? L.T("ADB przez sieć BEZ autoryzacji – pełny dostęp do urządzenia dla każdego w sieci")
                : L.T("ADB przez sieć włączone (wymaga zatwierdzenia na urządzeniu) – wyłącz, jeśli nieużywane"), true);
            if (x.TryGetValue("adb.model", out var model)) yield return (L.F("Model: {0}", model), false);
        }

        if (x.TryGetValue("mdns.service", out var mdnsService))
            yield return (L.F("Ogłaszane przez mDNS: {0}", L.Message(mdnsService)) + (x.TryGetValue("mdns.instance", out var inst) ? $" („{inst}”)" : ""), x.ContainsKey("mdns.risky"));
        if (x.TryGetValue("dns.rcode", out var rcode)) yield return (L.F("DNS potwierdzony (odpowiedź {0})", rcode), false);
        if (x.TryGetValue("dns.version", out var dnsVersion)) yield return (L.F("Ujawniona wersja: {0}", dnsVersion), true);
        if (x.ContainsKey("dns.versionNote")) yield return (L.T("Wersja może należeć do serwera nadrzędnego (przekazywanie zapytań) – wymaga weryfikacji"), false);
        if (x.ContainsKey("http.upnp")) yield return (L.T("Usługa UPnP dostępna w sieci"), true);
        if (x.TryGetValue("http.initialStatus", out var initial)) yield return (L.F("Strona po przekierowaniu (pierwsza odpowiedź HTTP {0})", initial), false);
        if (x.TryGetValue("rfb.version", out var rfb)) yield return (L.F("Protokół RFB {0}", rfb), false);
        if (svc?.ServiceName == "telnet") yield return (L.T("Telnet przesyła dane bez szyfrowania"), true);
        if (svc?.DetectionMethod == "port-hint") yield return (L.T("Usługa nie odpowiedziała na sondy – nazwa wynika tylko z numeru portu"), false);
    }
}
