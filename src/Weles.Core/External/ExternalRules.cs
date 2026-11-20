using System.Net;
using System.Text.RegularExpressions;
using Weles.Core.Enums;
using Weles.Core.Networking;

namespace Weles.Core.External;

/// <summary>
/// Evaluates a passive snapshot: e‑mail spoofing protection (SPF, DMARC), certificate issuance control (CAA), DNS
/// redundancy, internal addresses published in public DNS, dangling CNAMEs (possible subdomain takeover) and names that
/// suggest administrative services. Every finding quotes the record it is based on; nothing here was tested actively.
/// </summary>
public static partial class ExternalRules
{
    /// <summary>Labels that usually mean a management or internal service. A name alone proves nothing – the active scan confirms.</summary>
    private static readonly string[] AdminLabels =
    [
        "admin", "administrator", "panel", "cpanel", "whm", "plesk", "webmin", "phpmyadmin", "pma", "mysql", "db", "database",
        "vpn", "remote", "rdp", "citrix", "owa", "exchange", "autodiscover", "jenkins", "gitlab", "git", "jira", "confluence",
        "grafana", "kibana", "prometheus", "elastic", "portainer", "kubernetes", "k8s", "vcenter", "esxi", "proxmox", "ilo", "idrac",
        "ipmi", "mgmt", "management", "router", "firewall", "fortigate", "sophos", "pfsense", "dev", "staging", "stage", "test",
        "uat", "backup", "nas", "ftp", "sftp", "ssh", "intranet", "internal"
    ];

    /// <summary>SPF mechanisms that cost a DNS lookup; more than 10 makes SPF fail (RFC 7208 §4.6.4).</summary>
    private static readonly string[] LookupMechanisms = ["include", "a", "mx", "ptr", "exists", "redirect"];

    /// <summary>Remote administration, file sharing and database ports – they should not be reachable from the Internet.</summary>
    private static readonly HashSet<int> AdministrativePorts =
        [21, 22, 23, 135, 139, 161, 445, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8291, 9200, 10000, 11211, 27017, 5984, 2049, 111, 873, 902, 8006, 9090];

    public static bool IsAdministrativePort(int port) => AdministrativePorts.Contains(port);

    public static IReadOnlyList<ExternalFinding> Evaluate(ExternalSnapshot s)
    {
        var findings = new List<ExternalFinding>();
        if (IPAddress.TryParse(s.Domain, out _))
        {
            AddHostFindings(s, findings);
            return Sorted(findings);
        }

        var hasMx = s.OfType("MX").Any(r => r.Name == s.Domain);
        var spf = s.SpfRecords;
        if (spf.Count == 0)
        {
            findings.Add(hasMx
                ? new("SPF-MISSING", RiskLevel.Medium, "Brak rekordu SPF", $"Domena {s.Domain} ma rekordy MX (odbiera pocztę), ale nie publikuje SPF.",
                    "Opublikuj rekord TXT „v=spf1 … -all” z serwerami, które wysyłają pocztę w imieniu domeny – bez SPF łatwiej podszyć się pod nadawcę.")
                : new("SPF-MISSING", RiskLevel.Low, "Brak rekordu SPF", $"Domena {s.Domain} nie publikuje SPF ani MX.",
                    "Jeśli domena nie wysyła poczty, opublikuj „v=spf1 -all” – blokuje to podszywanie się pod jej adresy."));
        }
        else if (spf.Count > 1)
        {
            findings.Add(new("SPF-MULTIPLE", RiskLevel.Medium, "Kilka rekordów SPF", $"{spf.Count} rekordy TXT zaczynające się od v=spf1 – serwery pocztowe uznają SPF za błędny (permerror).",
                "Połącz wszystkie mechanizmy w jeden rekord SPF."));
        }

        if (spf.Count == 1)
        {
            var record = spf[0];
            var terms = record.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1).ToList();
            var all = terms.LastOrDefault(t => t.TrimStart('+', '-', '~', '?').Equals("all", StringComparison.OrdinalIgnoreCase));
            if (all is "all" or "+all")
            {
                findings.Add(new("SPF-PASS-ALL", RiskLevel.High, "SPF zezwala każdemu serwerowi na wysyłkę", $"SPF: {record}",
                    "Zamień „+all” na „-all” (lub „~all” w okresie przejściowym) – obecnie każdy serwer w Internecie przechodzi kontrolę SPF."));
            }
            else if (all == "?all")
            {
                findings.Add(new("SPF-NEUTRAL", RiskLevel.Medium, "SPF w trybie neutralnym (?all)", $"SPF: {record}",
                    "„?all” nie chroni przed podszywaniem się – użyj „-all” albo „~all”."));
            }
            else if (all is null && !terms.Any(t => t.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add(new("SPF-NO-ALL", RiskLevel.Low, "SPF bez końcowego „all”", $"SPF: {record}",
                    "Dodaj na końcu „-all” albo „~all” – bez tego serwery spoza listy dostają wynik neutralny."));
            }

            var lookups = terms.Count(t => LookupMechanisms.Contains(t.TrimStart('+', '-', '~', '?').Split(':', '/', '=')[0].ToLowerInvariant()));
            if (lookups > 10)
            {
                findings.Add(new("SPF-LOOKUPS", RiskLevel.Low, "SPF przekracza limit 10 zapytań DNS", $"{lookups} mechanizmów wymagających zapytań DNS w samym rekordzie (zagnieżdżone include nie są liczone).",
                    "Ogranicz liczbę include/a/mx – po przekroczeniu limitu SPF zwraca błąd i nie chroni domeny."));
            }
        }

        var dmarc = s.DmarcRecords;
        if (dmarc.Count == 0)
        {
            findings.Add(new("DMARC-MISSING", hasMx || spf.Count > 0 ? RiskLevel.Medium : RiskLevel.Low, "Brak rekordu DMARC", $"Brak rekordu TXT v=DMARC1 pod _dmarc.{s.Domain}.",
                "Opublikuj DMARC, zaczynając od „v=DMARC1; p=none; rua=mailto:…”, a po analizie raportów przejdź na p=quarantine lub p=reject."));
        }
        else if (dmarc.Count > 1)
        {
            findings.Add(new("DMARC-MULTIPLE", RiskLevel.Medium, "Kilka rekordów DMARC", $"{dmarc.Count} rekordy v=DMARC1 pod _dmarc.{s.Domain} – serwery pocztowe je ignorują.",
                "Zostaw jeden rekord DMARC."));
        }
        else if (DmarcPolicy().Match(dmarc[0]) is { Success: true } m && m.Groups[1].Value.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new("DMARC-NONE", RiskLevel.Low, "DMARC tylko monitoruje (p=none)", $"DMARC: {dmarc[0]}",
                "Po sprawdzeniu raportów zmień politykę na p=quarantine lub p=reject – p=none nie blokuje podszytych wiadomości."));
        }

        if (!s.OfType("CAA").Any())
        {
            findings.Add(new("CAA-MISSING", RiskLevel.Informational, "Brak rekordu CAA", $"Domena {s.Domain} nie ogranicza, które urzędy certyfikacji mogą wystawiać dla niej certyfikaty.",
                "Opcjonalnie dodaj rekord CAA (np. 0 issue \"letsencrypt.org\") dla używanego urzędu certyfikacji."));
        }

        var ns = s.OfType("NS").Where(r => r.Name == s.Domain).Select(r => r.Value).Distinct().ToList();
        if (ns.Count == 1)
        {
            findings.Add(new("NS-SINGLE", RiskLevel.Low, "Tylko jeden serwer nazw", $"NS: {ns[0]}",
                "Domena powinna mieć co najmniej dwa serwery DNS – awaria jednego wyłącza całą domenę."));
        }

        AddHostFindings(s, findings);

        if (s.WildcardAddresses.Count > 0)
        {
            findings.Add(new("DNS-WILDCARD", RiskLevel.Informational, "Rekord wieloznaczny (*) w DNS", $"Losowa, nieistniejąca nazwa w {s.Domain} zwraca {string.Join(", ", s.WildcardAddresses)}.",
                "To nie jest błąd, ale każda nazwa w domenie „istnieje” – subdomeny wskazujące tylko na ten adres oznaczono jako wieloznaczne."));
        }

        return Sorted(findings);
    }

    private static void AddHostFindings(ExternalSnapshot s, List<ExternalFinding> findings)
    {
        foreach (var host in s.Hosts)
        {
            if (host.DanglingCname)
            {
                findings.Add(new("DANGLING-CNAME", RiskLevel.High, "CNAME wskazuje na nieistniejącą nazwę", $"{host.Name} → {host.Cname} (NXDOMAIN)",
                    "Usuń rekord CNAME albo przywróć usługę docelową – jeśli docelowa nazwa należy do usługi chmurowej, ktoś inny może ją zarejestrować i przejąć subdomenę.", host.Name));
            }

            var internalAddresses = host.Addresses.Where(a => IPAddress.TryParse(a, out var ip) && AddressClassifier.Classify(ip) is AddressScope.Private or AddressScope.Loopback or AddressScope.LinkLocal or AddressScope.SharedAddressSpace).ToList();
            if (internalAddresses.Count > 0)
            {
                findings.Add(new("DNS-PRIVATE-ADDRESS", RiskLevel.Low, "Adres wewnętrzny w publicznym DNS", $"{host.Name} → {string.Join(", ", internalAddresses)}",
                    "Publiczny DNS ujawnia adresację sieci wewnętrznej – przenieś te nazwy do wewnętrznego DNS.", host.Name));
            }

            if (host.Resolves && !host.MatchesWildcard && host.Name != s.Domain && AdminLabel(host.Name, s.Domain) is { } label)
            {
                findings.Add(new("ADMIN-NAME", RiskLevel.Low, "Nazwa sugeruje usługę administracyjną lub testową", $"{host.Name} (etykieta „{label}”) → {string.Join(", ", host.Addresses.Take(3))}",
                    "Sprawdź, czy ta usługa musi być dostępna z Internetu; potwierdź otwarte porty skanem aktywnym tej nazwy.", host.Name));
            }
        }
    }

    private static string? AdminLabel(string name, string root)
    {
        var prefix = name.Length > root.Length ? name[..^(root.Length + 1)] : "";
        return prefix.Split('.', '-').FirstOrDefault(l => AdminLabels.Contains(l));
    }

    private static List<ExternalFinding> Sorted(List<ExternalFinding> f) => f.OrderByDescending(x => x.Level).ThenBy(x => x.Code).ThenBy(x => x.Host).ToList();

    [GeneratedRegex(@"(?:^|;)\s*p\s*=\s*([a-z]+)", RegexOptions.IgnoreCase)]
    private static partial Regex DmarcPolicy();
}
