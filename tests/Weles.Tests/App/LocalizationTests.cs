using System.Globalization;
using System.Text.RegularExpressions;
using Weles.App.Localization;
using Weles.App.Navigation;
using Weles.App.Services;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Models;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Core.Vulnerabilities;

namespace Weles.Tests.App;

/// <summary>The Polish → English dictionary must cover every text the UI can show.</summary>
public partial class LocalizationTests
{
    private static readonly string Root = FindRoot();

    private static string FindRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Weles.slnx"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found");
    }

    private sealed class English : IDisposable
    {
        private readonly CultureInfo _culture = CultureInfo.CurrentCulture, _ui = CultureInfo.CurrentUICulture;

        public English() => CultureInfo.CurrentCulture = CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en-GB");

        public void Dispose()
        {
            CultureInfo.CurrentCulture = _culture;
            CultureInfo.CurrentUICulture = _ui;
        }
    }

    [GeneratedRegex(@"[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]")]
    private static partial Regex PolishLetters();

    /// <summary>Common Polish words that would reveal an untranslated fragment without diacritics.</summary>
    [GeneratedRegex(@"\b(nie|jest|lub|przez|oraz|dla|bez|wersja|wersji|skan|skanu|zakres|zakresu|urządzenie|typowo|otwartych|hostów|adresów|portów|aktywnych|wykryta|pakiet|sprawdź)\b", RegexOptions.IgnoreCase)]
    private static partial Regex PolishWords();

    private static void AssertEnglish(string text, string source)
    {
        Assert.False(PolishLetters().IsMatch(text), $"Polish letters left: \"{text}\" (from \"{source}\")");
        Assert.False(PolishWords().IsMatch(text), $"Polish word left: \"{text}\" (from \"{source}\")");
    }

    [Fact]
    public void Every_text_used_by_the_ui_has_an_english_translation()
    {
        var literal = new Regex(@"L\.(?:T|F)\(""((?:[^""\\]|\\.)*)""");
        var missing = new List<string>();
        foreach (var file in Directory.EnumerateFiles(Path.Combine(Root, "src", "Weles.App"), "*.*", SearchOption.AllDirectories)
                     .Where(f => (f.EndsWith(".razor") || f.EndsWith(".cs")) && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")))
        {
            foreach (Match m in literal.Matches(File.ReadAllText(file)))
            {
                var key = Regex.Unescape(m.Groups[1].Value);
                if (!L.Dictionary.ContainsKey(key)) missing.Add($"{Path.GetFileName(file)}: {key}");
            }
        }

        Assert.Empty(missing);
    }

    [Fact]
    public void Navigation_texts_are_in_the_dictionary()
    {
        var texts = ModuleCatalog.All.SelectMany(m => new[] { m.Title, m.Group, m.Summary }.Concat(m.PlannedCapabilities));
        Assert.DoesNotContain(texts, t => !L.Dictionary.ContainsKey(t));
    }

    [Fact]
    public void Translations_are_english_and_keep_their_placeholders()
    {
        foreach (var (pl, en) in L.Dictionary)
        {
            Assert.False(string.IsNullOrWhiteSpace(en), pl);
            Assert.False(PolishLetters().IsMatch(en), $"{pl} → {en}");
            Assert.Equal(Regex.Matches(pl, @"\{\d+").Select(m => m.Value).Order(), Regex.Matches(en, @"\{\d+").Select(m => m.Value).Order());
        }
    }

    [Fact]
    public void Every_enum_label_is_translated()
    {
        using var _ = new English();
        var labels = Enum.GetValues<AssetStatus>().SelectMany(s => new[] { Labels.Of(s), Labels.Describe(s) })
            .Concat(Enum.GetValues<AssetType>().Select(Labels.Of))
            .Concat(Enum.GetValues<AssetCriticality>().Select(Labels.Of))
            .Concat(Enum.GetValues<ScanStatus>().Select(Labels.Of))
            .Concat(Enum.GetValues<Weles.Infrastructure.Scanning.ScanPhase>().Select(Labels.Of))
            .Concat(Enum.GetValues<VulnerabilityMatchStatus>().SelectMany(s => new[] { Labels.Of(s), Labels.Describe(s) }))
            .Concat(Enum.GetValues<FindingStatus>().Select(Labels.Of))
            .Concat(Enum.GetValues<RiskLevel>().Select(Labels.Of))
            .Where(l => l.Length > 0);
        foreach (var label in labels) AssertEnglish(label, label);
        Assert.Equal("5 devices", $"5 {Labels.Devices(5)}");
    }

    [Fact]
    public void Polish_stays_the_source_language()
    {
        var culture = CultureInfo.CurrentUICulture;
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("pl-PL");
        Assert.Equal("Podatności", L.T("Podatności"));
        Assert.Equal("Skan zakończony: 3 hostów, 1 otwartych portów, 0 rozpoznanych usług.", L.Message("Skan zakończony: 3 hostów, 1 otwartych portów, 0 rozpoznanych usług."));
        CultureInfo.CurrentUICulture = culture;
        using var _ = new English();
        Assert.Equal("Vulnerabilities", L.T("Podatności"));
        Assert.Equal("Ukryj: nieznany tekst", L.T("Ukryj: nieznany tekst")); // missing key falls back to Polish, never a raw key
    }

    /// <summary>Messages taken from a real user database (2026-11-19) – stored in Polish by earlier scans.</summary>
    [Theory]
    [InlineData("Dopasowanie podatności: 37 otwartych dla 4 urządzeń (nowe: 37, rozwiązane: 0).", "Vulnerability matching: 37 open for 4 devices (new: 37, resolved: 0).")]
    [InlineData("Wykrywanie hostów zakończone: 12 aktywnych z 254 adresów (w tym 1 wyłącznie z tablicy ARP).", "Host discovery finished: 12 live out of 254 addresses (1 from the ARP table only).")]
    [InlineData("Wykrywanie hostów zakończone: 3 aktywnych z 254 adresów.", "Host discovery finished: 3 live out of 254 addresses.")]
    [InlineData("Rozpoczęto skan zakresu „Sieć lokalna 192.168.0.0/24” (porty: quick).", "Started scanning scope “Local network 192.168.0.0/24” (ports: quick).")]
    [InlineData("Typ wynika z usług ogłaszanych przez mDNS: Pilot Android TV, Google Cast", "Type derived from services announced over mDNS: Android TV remote, Google Cast")]
    [InlineData("Producent sprzętu sieciowego: Tenda Technology Co.,Ltd.Dongguan branch", "Network equipment vendor: Tenda Technology Co.,Ltd.Dongguan branch")]
    [InlineData("Komputer, na którym działa WELES (Linux)", "The computer running WELES (Linux)")]
    [InlineData("TTL 64 (typowo Linux/Unix) – niska pewność", "TTL 64 (typical of Linux/Unix) – low confidence")]
    [InlineData("Brama domyślna segmentu sieci\nLosowy adres MAC – zwykle telefon, tablet lub laptop z ochroną prywatności", "Default gateway of the network segment\nRandom MAC address – usually a phone, tablet or laptop with privacy protection")]
    [InlineData("mDNS: 2 urządzeń w zakresie ogłasza 3 usług.", "mDNS: 2 devices in scope announce 3 services.")]
    [InlineData("TP-LINK (192.168.0.1)", "TP-LINK (192.168.0.1)")]
    public void Stored_messages_are_translated_for_display(string stored, string expected)
    {
        using var _ = new English();
        Assert.Equal(expected, L.Message(stored));
    }

    [Fact]
    public void Texts_generated_by_the_core_are_fully_translated()
    {
        var generated = new List<string>();

        // Vulnerability match reasons – every note the matcher can add.
        AffectedProductRecord[] ssh = [new("a", "openbsd", "openssh", VersionEndExcluding: "9.3", Condition: "microsoft:windows")];
        generated.Add(VulnerabilityMatcher.Match(ssh, [new SoftwareEvidence("OpenSSH", "openbsd", "openssh", "8.9", 55, 22, "Ubuntu", "wersja z zapytania version.bind może należeć do serwera nadrzędnego (przekazywanie zapytań)")], [])!.Reason);
        generated.Add(VulnerabilityMatcher.Match([new("a", "openbsd", "openssh", VersionEndExcluding: "8.9p1")], [new SoftwareEvidence("OpenSSH", "openbsd", "openssh", "8.9", 80, 22)], [])!.Reason);
        generated.Add(VulnerabilityMatcher.Match([new("a", "openbsd", "openssh")], [new SoftwareEvidence("OpenSSH", "openbsd", "openssh", "8.9p1", 95, 22)], [])!.Reason);
        generated.Add(VulnerabilityMatcher.Match(
            [new("h", "tp-link", "tl-wr841n", Version: "v9"), new("o", "tp-link", "tl-wr841n_firmware", VersionEndIncluding: "3.13.9"), new("o", "tp-link", "tl-wr841n_firmware", Version: "3.16.9")],
            [], [new HardwareEvidence("TP-Link TL-WR841N", "tp-link", "tl-wr841n")])!.Reason);

        // Classification reasons.
        generated.AddRange(AssetClassifier.Classify(new HostEvidence([22, 80], [new ServiceIdentification { ServiceName = "http", Method = "http-request", Extra = new() { ["http.panel"] = "TP-Link", ["device.model"] = "TP-Link TL-WR841N" } }], "TP-LINK TECHNOLOGIES", 64, true, null)).Reasons);
        generated.AddRange(AssetClassifier.Classify(new HostEvidence([], [], null, 128, false, null, HasRandomizedMac: true)).Reasons);
        generated.AddRange(AssetClassifier.Classify(new HostEvidence([1883], [], "Espressif Inc.", 255, false, null, MdnsServiceTypes: ["_googlecast._tcp", "_workstation._tcp"])).Reasons);

        // Validation errors.
        foreach (var bad in (string[])["300.1.1.1", "10.0.0.0/33", "10.0.0.0/8", "10.0.0.9-10.0.0.1", "fe80::/64", "!!"])
        {
            TargetParser.TryParse(bad, out _, out var error);
            generated.Add(error!);
        }

        PortSpecification.TryParse("22,99999", out _, out var portError);
        generated.Add(portError!);

        // Change history.
        DiscoveredHost Host(string ip, string mac, string? version, params int[] ports) => new()
        {
            IpAddress = ip, MacAddress = mac, Hostname = "nas", AssetTypeGuess = AssetType.Nas,
            Ports = ports.Select(p => new DiscoveredPort { Port = p, State = PortState.Open, Service = new DiscoveredService { ServiceName = "ssh", Product = "OpenSSH", Version = version } }).ToList()
        };
        generated.AddRange(ObservationComparer.Compare(Host("10.0.0.1", "aa:aa:aa:aa:aa:aa", "8.9p1", 22, 80), Host("10.0.0.2", "bb:bb:bb:bb:bb:bb", "9.6p1", 22, 443)).Select(c => c.Description));

        generated.Add(new AffectedProductRecord("a", "x", "y").Describe());

        // Risk engine: every rule (title, category, recommendation, evidence) and every score factor.
        var now = new DateTime(2026, 11, 19, 0, 0, 0, DateTimeKind.Utc);
        foreach (var rule in Weles.Core.Risk.RiskRules.All) generated.AddRange([rule.Title, rule.Category, rule.Recommendation]);
        Weles.Core.Risk.ServiceFacts Svc(int port, string name, Dictionary<string, string> extra, Weles.Core.Risk.CertificateFacts? cert = null, string method = "banner") =>
            new(port, name, "Product", 90, method, false, extra, cert);
        var services = new[]
        {
            Svc(5555, "adb", new() { ["adb.auth"] = "none" }), Svc(5556, "adb", new() { ["adb.auth"] = "required" }), Svc(2375, "docker", []),
            Svc(6379, "redis", new() { ["redis.auth"] = "none" }), Svc(9000, "http", new() { ["http.panel"] = "Portainer", ["http.panelCategory"] = "devops" }),
            Svc(23, "telnet", []), Svc(80, "http", new() { ["http.basicOverHttp"] = "1", ["http.missingHeaders"] = "X-Frame-Options,X-Content-Type-Options", ["http.upnp"] = "1", ["http.poweredBy"] = "PHP/7.4" }),
            Svc(8080, "http", new() { ["http.requiresAuth"] = "1" }), Svc(21, "ftp", [], method: "port-hint"), Svc(3389, "rdp", new() { ["rdp.security"] = "RDP standard" }),
            Svc(3390, "rdp", []), Svc(5900, "vnc", []), Svc(445, "microsoft-ds", []), Svc(5432, "postgresql", new() { ["postgresql.ssl"] = "unsupported" }),
            Svc(1883, "mqtt", []), Svc(53, "dns", new() { ["dns.version"] = "9.18" }),
            Svc(443, "https", new() { ["tls.legacy"] = "TLS 1.0" }, new Weles.Core.Risk.CertificateFacts(now.AddDays(-1), true, null, 1024, "RSA")),
            Svc(8443, "https", [], new Weles.Core.Risk.CertificateFacts(now.AddDays(90), false, false, 2048, "RSA"))
        };
        var findings = services.SelectMany(x => Weles.Core.Risk.RiskRules.Evaluate(x, now)).ToList();
        Assert.Equal(Weles.Core.Risk.RiskRules.All.Count, findings.Select(f => f.Rule.Id).Distinct().Count()); // every rule exercised
        generated.AddRange(findings.Select(f => f.Evidence));
        var risk = Weles.Core.Risk.RiskEngine.ScoreAsset(new Weles.Core.Risk.AssetRiskInput(AssetType.Router, AssetCriticality.High, true, true, 9, findings,
        [
            new("CVE-2017-7494", 9.8, 0.94, true, VulnerabilityMatchStatus.NeedsVerification, 445, "Samba", "4.4", now.AddYears(-9)),
            new("CVE-2020-1", null, 0.02, false, VulnerabilityMatchStatus.Confirmed, 445, "Samba", "4.4", now.AddYears(-3)),
            new("CVE-2023-2", 8.8, null, false, VulnerabilityMatchStatus.InsufficientData, null, "TP-Link TL-WR841N", null, now.AddYears(-1))
        ], [445], 2), now);
        generated.AddRange(risk.Factors.Select(f => f.Text));
        generated.AddRange(risk.Issues.SelectMany(i => i.Reasons.Append(i.Title).Append(i.Recommendation)));
        foreach (var c in Enum.GetValues<AssetCriticality>())
        {
            generated.AddRange(Weles.Core.Risk.RiskEngine.ScoreAsset(new Weles.Core.Risk.AssetRiskInput(AssetType.Server, c, false, false, 1, findings.Take(1).ToList(), [], []), now).Factors.Select(f => f.Text));
        }

        generated.AddRange(Weles.Core.Risk.RiskEngine.ScoreAsset(new Weles.Core.Risk.AssetRiskInput(AssetType.MobileDevice, AssetCriticality.Medium, false, false, 0, [], [], []), now).Factors.Select(f => f.Text));
        generated.AddRange(Weles.Core.Risk.RiskEngine.Posture([("TP-LINK (192.168.0.1)", 92), ("NAS", 70), ("TV", 5)]).Factors.Select(f => f.Text));
        generated.AddRange(Weles.Core.Risk.RiskEngine.Posture([]).Factors.Select(f => f.Text));
        // Attack paths: every step text, local and Internet variants, every device role.
        foreach (var (type, gateway, isPublic, crit) in new[] { (AssetType.Router, true, false, AssetCriticality.Critical), (AssetType.Nas, false, true, AssetCriticality.High), (AssetType.IoTDevice, false, false, AssetCriticality.Medium), (AssetType.LinuxHost, false, false, AssetCriticality.Low) })
        {
            var asset = new Weles.Core.Risk.PathAsset(1, "TP-LINK (192.168.0.1)", "192.168.0.1", type, crit, gateway, isPublic, 7, "192.168.0.0/24 · TP-LINK c0:4a:00:ee:19:4a", 5,
            [
                new("Telnet – logowanie bez szyfrowania", 70, 23, null, 70, "Dowód ze skanu: Port 23: usługa Telnet", false),
                new("Zaktualizuj OpenSSH 8.4p1 (port 22)", 78, 22, "CVE-2023-38408", 45, "Dopasowanie wymaga weryfikacji (np. pakiet dystrybucji z przeniesionymi poprawkami)", true),
                new("Sprawdź firmware: TP-Link TL-WR841N", 40, null, "CVE-2020-1", 20, "Za mało danych (np. nieznana wersja firmware)", false),
                new("Usługa UPnP dostępna w sieci", 40, 1900, null, 90, "Dowód ze skanu: Port 1900: UPnP", false, IsUpnp: true)
            ]);
            foreach (var path in Weles.Core.Risk.AttackPathEngine.Build([asset], 50))
            {
                generated.Add(path.Title);
                generated.AddRange(path.Steps.SelectMany(st => new[] { st.Title, st.Justification }));
            }
        }

        generated.AddRange(["Uruchomiono skan #12.", "Pominięto: zakres nie jest zatwierdzony.", "Pominięto: komputer jest teraz w innej sieci niż ta, w której zatwierdzono i skanowano zakres (inny router).", "Pominięto: Dla tego zakresu trwa już skan."]);
        generated.Add("Ocena ryzyka: Security Posture Score 54/100, urządzenia Critical: 1, High: 2 (nowe problemy konfiguracji: 3, rozwiązane: 0).");
        Assert.True(generated.Count > 15);

        using var english = new English();
        foreach (var text in generated) AssertEnglish(L.Message(text), text);
    }
}
