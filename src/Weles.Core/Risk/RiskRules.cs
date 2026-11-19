using Weles.Core.Enums;

namespace Weles.Core.Risk;

/// <summary>A configuration weakness WELES can see from the network – what it is and what to do about it.</summary>
/// <param name="BaseScore">0–100 before asset context (criticality, exposure, role).</param>
/// <param name="AttackTechniques">MITRE ATT&amp;CK techniques the weakness enables (IDs from attack.mitre.org).</param>
public sealed record RiskRule(string Id, string Title, string Category, int BaseScore, string Recommendation, IReadOnlyList<string> AttackTechniques);

/// <summary>What the scan recorded about one open port (built from DiscoveredService).</summary>
public sealed record ServiceFacts(
    int Port,
    string? ServiceName,
    string? Product,
    int Confidence,
    string? DetectionMethod,
    bool IsTls,
    IReadOnlyDictionary<string, string> Extra,
    CertificateFacts? Certificate = null)
{
    /// <summary>Only the port number is known – the service behind it was not confirmed.</summary>
    public bool PortOnly => DetectionMethod is null or "port-hint";
}

public sealed record CertificateFacts(DateTime NotAfter, bool IsSelfSigned, bool? HostnameMatches, int? KeySize, string? KeyAlgorithm);

/// <summary>A rule that fired on a port, with the evidence that made it fire.</summary>
public sealed record ConfigFinding(RiskRule Rule, int? Port, string Evidence, int Confidence);

/// <summary>
/// Configuration rules evaluated on what the scan observed. Rules never guess: each needs explicit evidence (a protocol
/// answer, a header, a certificate) or – for "service exposed" rules – an open port, with lower confidence when the
/// service was recognised only from the port number.
/// </summary>
public static class RiskRules
{
    public const string CategoryAccess = "dostęp";
    public const string CategoryEncryption = "szyfrowanie";
    public const string CategoryExposure = "ekspozycja";
    public const string CategoryDisclosure = "ujawnianie informacji";

    public static readonly RiskRule AdbNoAuth = new("ADB-NOAUTH", "Debugowanie ADB przez sieć bez autoryzacji", CategoryAccess, 95,
        "Wyłącz debugowanie ADB przez sieć (Opcje programisty → Debugowanie bezprzewodowe / ADB przez sieć) albo ogranicz je do zaufanej sieci.", ["T1021", "T1219"]);
    public static readonly RiskRule AdbEnabled = new("ADB-ENABLED", "Debugowanie ADB przez sieć włączone", CategoryAccess, 45,
        "Wyłącz debugowanie ADB przez sieć, jeśli nie jest używane – każde zatwierdzenie na urządzeniu daje pełny dostęp.", ["T1021"]);
    public static readonly RiskRule DockerApi = new("DOCKER-API", "API Dockera bez TLS", CategoryAccess, 95,
        "Nie wystawiaj API Dockera na TCP bez TLS i uwierzytelniania klienta; używaj gniazda unix lub portu 2376 z certyfikatami.", ["T1610", "T1190"]);
    public static readonly RiskRule RedisNoAuth = new("REDIS-NOAUTH", "Redis bez uwierzytelniania", CategoryAccess, 85,
        "Włącz uwierzytelnianie (requirepass / ACL) i ogranicz nasłuch Redis do localhost lub sieci aplikacji.", ["T1210", "T1190"]);
    /// <summary>
    /// The start page answers without HTTP authentication. Many devices log in through a form on that page, so this is
    /// exposure of a management interface – not proof that it can be used without a password.
    /// </summary>
    public static readonly RiskRule AdminPanelExposed = new("ADMIN-PANEL-EXPOSED", "Panel administracyjny dostępny w sieci", CategoryExposure, 40,
        "Ogranicz dostęp do panelu (osobna sieć zarządzająca, VPN, lista adresów), używaj silnego hasła i wyłącz zarządzanie z sieci gości.", ["T1190", "T1078"]);
    public static readonly RiskRule Telnet = new("TELNET", "Telnet – logowanie bez szyfrowania", CategoryEncryption, 70,
        "Wyłącz Telnet i używaj SSH; jeśli urządzenie nie ma SSH, odizoluj je od sieci użytkowników.", ["T1040", "T1110"]);
    public static readonly RiskRule HttpBasicCleartext = new("HTTP-BASIC-CLEARTEXT", "Hasło HTTP Basic przesyłane bez szyfrowania", CategoryEncryption, 65,
        "Włącz HTTPS dla interfejsu WWW albo wyłącz dostęp przez HTTP; zmień hasło, jeśli było używane w niezaufanej sieci.", ["T1040", "T1110"]);
    public static readonly RiskRule LoginOverHttp = new("LOGIN-HTTP", "Strona logowania bez szyfrowania", CategoryEncryption, 40,
        "Udostępniaj panel tylko przez HTTPS (przekierowanie z HTTP).", ["T1040", "T1557"]);
    public static readonly RiskRule Ftp = new("FTP-CLEARTEXT", "FTP bez szyfrowania", CategoryEncryption, 45,
        "Zastąp FTP protokołem SFTP lub FTPS; nie przesyłaj nim haseł ani poufnych plików.", ["T1040", "T1110"]);
    public static readonly RiskRule RdpNoNla = new("RDP-NO-NLA", "Pulpit zdalny (RDP) bez uwierzytelniania na poziomie sieci (NLA)", CategoryAccess, 65,
        "Włącz NLA dla usług pulpitu zdalnego i ogranicz dostęp do RDP (VPN, zapora).", ["T1021.001", "T1110"]);
    public static readonly RiskRule RdpExposed = new("RDP-EXPOSED", "Pulpit zdalny (RDP) dostępny w sieci", CategoryExposure, 35,
        "Ogranicz dostęp do RDP do potrzebnych adresów (zapora) i włącz blokadę konta po nieudanych logowaniach.", ["T1021.001", "T1110"]);
    public static readonly RiskRule Vnc = new("VNC-EXPOSED", "Pulpit zdalny VNC dostępny w sieci", CategoryAccess, 55,
        "Wyłącz VNC albo udostępniaj go tylko przez tunel SSH/VPN z silnym hasłem.", ["T1021.005", "T1110"]);
    public static readonly RiskRule SmbExposed = new("SMB-EXPOSED", "Udostępnianie plików SMB dostępne w sieci", CategoryExposure, 40,
        "Wyłącz SMBv1, ogranicz udziały do potrzebnych użytkowników i nie udostępniaj SMB poza siecią lokalną.", ["T1021.002", "T1210"]);
    public static readonly RiskRule DatabaseExposed = new("DB-EXPOSED", "Baza danych dostępna w sieci", CategoryExposure, 35,
        "Nasłuchuj tylko na adresie aplikacji (np. localhost), ogranicz dostęp zaporą i wymagaj szyfrowanych połączeń.", ["T1190", "T1078"]);
    public static readonly RiskRule PostgresNoSsl = new("POSTGRES-NO-SSL", "PostgreSQL bez obsługi SSL", CategoryEncryption, 25,
        "Włącz ssl = on w postgresql.conf i wymagaj hostssl w pg_hba.conf.", ["T1040"]);
    public static readonly RiskRule Mqtt = new("MQTT-CLEARTEXT", "Broker MQTT bez szyfrowania", CategoryEncryption, 40,
        "Używaj MQTT przez TLS (8883) z uwierzytelnianiem klientów; wyłącz anonimowy dostęp.", ["T1040", "T1078"]);
    public static readonly RiskRule TlsLegacy = new("TLS-LEGACY", "Przestarzałe protokoły TLS 1.0/1.1", CategoryEncryption, 40,
        "Wyłącz TLS 1.0 i 1.1; pozostaw TLS 1.2 i 1.3.", ["T1557"]);
    public static readonly RiskRule CertExpired = new("CERT-EXPIRED", "Wygasły certyfikat TLS", CategoryEncryption, 35,
        "Odnów certyfikat; wygasłe certyfikaty uczą użytkowników ignorowania ostrzeżeń przeglądarki.", ["T1557"]);
    public static readonly RiskRule CertWeakKey = new("CERT-WEAK-KEY", "Słaby klucz certyfikatu", CategoryEncryption, 40,
        "Wygeneruj nowy certyfikat z kluczem RSA ≥ 2048 bitów lub ECDSA.", ["T1557"]);
    public static readonly RiskRule CertSelfSigned = new("CERT-SELF-SIGNED", "Certyfikat samopodpisany", CategoryEncryption, 15,
        "Użyj certyfikatu z zaufanego urzędu (także wewnętrznego), żeby przeglądarki mogły wykryć podszywanie się.", ["T1557"]);
    public static readonly RiskRule CertNameMismatch = new("CERT-NAME-MISMATCH", "Nazwa w certyfikacie nie pasuje do hosta", CategoryEncryption, 15,
        "Wystaw certyfikat z nazwą, pod którą usługa jest używana.", ["T1557"]);
    public static readonly RiskRule Upnp = new("UPNP-EXPOSED", "Usługa UPnP dostępna w sieci", CategoryExposure, 25,
        "Wyłącz UPnP na routerze, jeśli nie jest potrzebne – pozwala programom w sieci otwierać porty na zewnątrz.", ["T1133"]);
    public static readonly RiskRule HttpHeaders = new("HTTP-HEADERS", "Brak nagłówków bezpieczeństwa HTTP", CategoryDisclosure, 10,
        "Dodaj nagłówki X-Content-Type-Options, X-Frame-Options / CSP i (dla HTTPS) Strict-Transport-Security.", ["T1189"]);
    public static readonly RiskRule VersionDisclosure = new("VERSION-DISCLOSURE", "Usługa ujawnia wersję oprogramowania", CategoryDisclosure, 5,
        "Ukryj numer wersji w odpowiedziach usługi (np. version.bind, nagłówek Server/X-Powered-By).", ["T1592"]);

    public static IReadOnlyList<RiskRule> All { get; } =
    [
        AdbNoAuth, AdbEnabled, DockerApi, RedisNoAuth, AdminPanelExposed, Telnet, HttpBasicCleartext, LoginOverHttp, Ftp, RdpNoNla, RdpExposed, Vnc,
        SmbExposed, DatabaseExposed, PostgresNoSsl, Mqtt, TlsLegacy, CertExpired, CertWeakKey, CertSelfSigned, CertNameMismatch, Upnp, HttpHeaders, VersionDisclosure
    ];

    public static RiskRule? Find(string id) => All.FirstOrDefault(r => r.Id == id);

    private static readonly HashSet<int> DatabasePorts = [1433, 1521, 3306, 5432, 6379, 9200, 27017, 5984, 11211];

    public static IEnumerable<ConfigFinding> Evaluate(ServiceFacts s, DateTime now)
    {
        var x = s.Extra;
        var name = s.ServiceName ?? "";
        var portOnlyConfidence = s.PortOnly ? 60 : Math.Max(s.Confidence, 70);

        if (x.TryGetValue("adb.auth", out var adb))
        {
            yield return adb == "none"
                ? new ConfigFinding(AdbNoAuth, s.Port, $"Port {s.Port}: ADB odpowiedział bez autoryzacji", 95)
                : new ConfigFinding(AdbEnabled, s.Port, $"Port {s.Port}: ADB wymaga zatwierdzenia na urządzeniu", 90);
        }

        if (s.Port == 2375 || name == "docker") yield return new ConfigFinding(DockerApi, s.Port, $"Port {s.Port} otwarty (API Dockera bez TLS)", portOnlyConfidence);
        if (x.TryGetValue("redis.auth", out var redis) && redis == "none") yield return new ConfigFinding(RedisNoAuth, s.Port, $"Port {s.Port}: Redis odpowiedział na PING bez hasła", 95);

        var requiresAuth = x.ContainsKey("http.requiresAuth");
        if (!requiresAuth && x.GetValueOrDefault("http.panelCategory") is "admin-panel" or "devops" && x.TryGetValue("http.panel", out var panel))
        {
            yield return new ConfigFinding(AdminPanelExposed, s.Port, $"Port {s.Port}: {panel} – strona startowa bez uwierzytelnienia HTTP (logowanie może być w formularzu strony)", 80);
        }

        if (name == "telnet") yield return new ConfigFinding(Telnet, s.Port, $"Port {s.Port}: usługa Telnet", portOnlyConfidence);
        if (x.ContainsKey("http.basicOverHttp")) yield return new ConfigFinding(HttpBasicCleartext, s.Port, $"Port {s.Port}: HTTP Basic bez TLS", 95);
        else if (!s.IsTls && (requiresAuth || x.GetValueOrDefault("http.panelCategory") == "login-page") && !x.ContainsKey("http.redirectsToHttps"))
        {
            yield return new ConfigFinding(LoginOverHttp, s.Port, $"Port {s.Port}: logowanie przez HTTP", 85);
        }

        if (name == "ftp" && !s.IsTls) yield return new ConfigFinding(Ftp, s.Port, $"Port {s.Port}: FTP", portOnlyConfidence);

        if (name == "rdp" || s.Port == 3389)
        {
            yield return x.TryGetValue("rdp.security", out var rdp) && !rdp.StartsWith("NLA", StringComparison.Ordinal)
                ? new ConfigFinding(RdpNoNla, s.Port, $"Port {s.Port}: RDP – zabezpieczenie {rdp}", 90)
                : new ConfigFinding(RdpExposed, s.Port, $"Port {s.Port}: RDP", portOnlyConfidence);
        }

        if (name is "vnc" or "rfb" || x.ContainsKey("rfb.version")) yield return new ConfigFinding(Vnc, s.Port, $"Port {s.Port}: VNC", portOnlyConfidence);
        if (s.Port == 445 || name == "microsoft-ds") yield return new ConfigFinding(SmbExposed, s.Port, $"Port {s.Port}: SMB", portOnlyConfidence);

        if (DatabasePorts.Contains(s.Port) && !(s.Port == 6379 && x.GetValueOrDefault("redis.auth") == "none"))
        {
            yield return new ConfigFinding(DatabaseExposed, s.Port, $"Port {s.Port}: {s.Product ?? name}", portOnlyConfidence);
        }

        if (x.GetValueOrDefault("postgresql.ssl") is { } pg && pg != "supported") yield return new ConfigFinding(PostgresNoSsl, s.Port, $"Port {s.Port}: PostgreSQL bez SSL", 90);
        if (s.Port == 1883 || name == "mqtt") yield return new ConfigFinding(Mqtt, s.Port, $"Port {s.Port}: MQTT", portOnlyConfidence);
        if (x.ContainsKey("tls.legacy")) yield return new ConfigFinding(TlsLegacy, s.Port, $"Port {s.Port}: akceptuje TLS 1.0/1.1", 95);

        if (s.Certificate is { } c)
        {
            if (c.NotAfter < now) yield return new ConfigFinding(CertExpired, s.Port, $"Port {s.Port}: certyfikat wygasł {c.NotAfter:yyyy-MM-dd}", 95);
            if (c.KeySize is { } size && c.KeyAlgorithm?.Contains("RSA", StringComparison.OrdinalIgnoreCase) == true && size < 2048)
            {
                yield return new ConfigFinding(CertWeakKey, s.Port, $"Port {s.Port}: klucz RSA {size} bit", 95);
            }

            if (c.IsSelfSigned) yield return new ConfigFinding(CertSelfSigned, s.Port, $"Port {s.Port}: certyfikat samopodpisany", 95);
            else if (c.HostnameMatches == false) yield return new ConfigFinding(CertNameMismatch, s.Port, $"Port {s.Port}: nazwa w certyfikacie inna niż host", 90);
        }

        if (x.ContainsKey("http.upnp") || s.Port == 1900) yield return new ConfigFinding(Upnp, s.Port, $"Port {s.Port}: UPnP", x.ContainsKey("http.upnp") ? 90 : portOnlyConfidence);
        if (x.TryGetValue("http.missingHeaders", out var missing)) yield return new ConfigFinding(HttpHeaders, s.Port, $"Port {s.Port}: brak {missing.Replace(",", ", ")}", 90);
        if (x.TryGetValue("dns.version", out var dnsVersion)) yield return new ConfigFinding(VersionDisclosure, s.Port, $"Port {s.Port}: version.bind = {dnsVersion}", 90);
        else if (x.TryGetValue("http.poweredBy", out var powered)) yield return new ConfigFinding(VersionDisclosure, s.Port, $"Port {s.Port}: X-Powered-By: {powered}", 90);
    }
}

/// <summary>Names of the MITRE ATT&amp;CK techniques referenced by the rules (Enterprise matrix).</summary>
public static class AttackTechniques
{
    public static readonly IReadOnlyDictionary<string, string> Names = new Dictionary<string, string>
    {
        ["T1021"] = "Remote Services",
        ["T1021.001"] = "Remote Services: Remote Desktop Protocol",
        ["T1021.002"] = "Remote Services: SMB/Windows Admin Shares",
        ["T1021.005"] = "Remote Services: VNC",
        ["T1040"] = "Network Sniffing",
        ["T1078"] = "Valid Accounts",
        ["T1110"] = "Brute Force",
        ["T1133"] = "External Remote Services",
        ["T1189"] = "Drive-by Compromise",
        ["T1190"] = "Exploit Public-Facing Application",
        ["T1210"] = "Exploitation of Remote Services",
        ["T1219"] = "Remote Access Software",
        ["T1557"] = "Adversary-in-the-Middle",
        ["T1592"] = "Gather Victim Host Information",
        ["T1610"] = "Deploy Container"
    };

    public static string Url(string id) => $"https://attack.mitre.org/techniques/{id.Replace('.', '/')}/";
}
