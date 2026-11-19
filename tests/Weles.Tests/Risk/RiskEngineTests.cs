using Weles.Core.Enums;
using Weles.Core.Risk;

namespace Weles.Tests.Risk;

public class RiskEngineTests
{
    private static readonly DateTime Now = new(2026, 11, 19, 12, 0, 0, DateTimeKind.Utc);

    private static ServiceFacts Svc(int port, string? name, string method = "banner", bool tls = false, Dictionary<string, string>? extra = null, CertificateFacts? cert = null, int confidence = 90) =>
        new(port, name, null, confidence, method, tls, extra ?? [], cert);

    private static List<string> Rules(ServiceFacts s) => RiskRules.Evaluate(s, Now).Select(f => f.Rule.Id).ToList();

    [Fact]
    public void Rules_fire_only_on_explicit_evidence()
    {
        Assert.Equal(["ADB-NOAUTH"], Rules(Svc(5555, "adb", extra: new() { ["adb.auth"] = "none" })));
        Assert.Equal(["ADB-ENABLED"], Rules(Svc(5555, "adb", extra: new() { ["adb.auth"] = "required" })));
        Assert.Equal(["REDIS-NOAUTH"], Rules(Svc(6379, "redis", extra: new() { ["redis.auth"] = "none" })));
        Assert.Equal(["DB-EXPOSED"], Rules(Svc(6379, "redis", extra: new() { ["redis.auth"] = "required" })));
        Assert.Equal(["TELNET"], Rules(Svc(23, "telnet")));
        Assert.Equal(["RDP-NO-NLA"], Rules(Svc(3389, "rdp", extra: new() { ["rdp.security"] = "RDP standard" })));
        Assert.Equal(["RDP-EXPOSED"], Rules(Svc(3389, "rdp", extra: new() { ["rdp.security"] = "NLA (CredSSP)" })));
        Assert.Equal(["HTTP-BASIC-CLEARTEXT"], Rules(Svc(80, "http", extra: new() { ["http.basicOverHttp"] = "1", ["http.requiresAuth"] = "1" })));
        Assert.Equal(["LOGIN-HTTP"], Rules(Svc(80, "http", extra: new() { ["http.panel"] = "Panel logowania", ["http.panelCategory"] = "login-page" })));
        Assert.Empty(Rules(Svc(80, "http", extra: new() { ["http.panelCategory"] = "login-page", ["http.redirectsToHttps"] = "1" })));
        Assert.Equal(["ADMIN-PANEL-EXPOSED"], Rules(Svc(9000, "http", extra: new() { ["http.panel"] = "Portainer", ["http.panelCategory"] = "devops" })));
        // With a login the panel is no longer "open", but the password still travels over plain HTTP.
        Assert.Equal(["LOGIN-HTTP"], Rules(Svc(9000, "http", extra: new() { ["http.panel"] = "Portainer", ["http.panelCategory"] = "devops", ["http.requiresAuth"] = "1" })));
        Assert.Empty(Rules(Svc(9443, "https", tls: true, extra: new() { ["http.panel"] = "Portainer", ["http.panelCategory"] = "devops", ["http.requiresAuth"] = "1" })));
        Assert.Empty(Rules(Svc(22, "ssh")));
        Assert.Empty(Rules(Svc(443, "https", tls: true)));

        var certs = Rules(Svc(443, "https", tls: true, extra: new() { ["tls.legacy"] = "TLS 1.0" }, cert: new CertificateFacts(Now.AddDays(-3), true, null, 1024, "RSA")));
        Assert.Equal(["TLS-LEGACY", "CERT-EXPIRED", "CERT-WEAK-KEY", "CERT-SELF-SIGNED"], certs);
    }

    [Fact]
    public void Port_only_findings_carry_lower_confidence_and_score()
    {
        var byPort = RiskRules.Evaluate(Svc(445, "microsoft-ds", method: "port-hint", confidence: 20), Now).Single();
        var byProbe = RiskRules.Evaluate(Svc(445, "microsoft-ds", confidence: 90), Now).Single();
        Assert.Equal(60, byPort.Confidence);
        Assert.True(byProbe.Confidence >= 70);

        var input = (ConfigFinding f) => new AssetRiskInput(AssetType.LinuxHost, AssetCriticality.Medium, false, false, 1, [f], [], []);
        Assert.True(RiskEngine.ScoreAsset(input(byPort), Now).Score < RiskEngine.ScoreAsset(input(byProbe), Now).Score);
    }

    private static VulnerabilityFacts Cve(string id, double cvss, bool kev = false, double? epss = null, VulnerabilityMatchStatus status = VulnerabilityMatchStatus.Confirmed, int? port = 22, string product = "OpenSSH", DateTime? published = null) =>
        new(id, cvss, epss, kev, status, port, product, "8.4p1", published ?? Now.AddYears(-1));

    [Fact]
    public void Vulnerability_score_uses_cvss_kev_epss_and_match_certainty()
    {
        Assert.Equal(75, RiskEngine.ScoreVulnerability(Cve("A", 7.5)).Score);
        Assert.Equal(95, RiskEngine.ScoreVulnerability(Cve("A", 7.5, kev: true)).Score);
        Assert.Equal(100, RiskEngine.ScoreVulnerability(Cve("A", 9.8, kev: true, epss: 0.9)).Score);
        Assert.Equal(85, RiskEngine.ScoreVulnerability(Cve("A", 7.5, epss: 0.2)).Score);
        Assert.Equal(45, RiskEngine.ScoreVulnerability(Cve("A", 7.5, status: VulnerabilityMatchStatus.NeedsVerification)).Score, 3);
        Assert.Equal(18.75, RiskEngine.ScoreVulnerability(Cve("A", 7.5, status: VulnerabilityMatchStatus.InsufficientData)).Score, 3);
        Assert.Contains(RiskEngine.ScoreVulnerability(Cve("A", 7.5, kev: true)).Reasons, r => r.Contains("CISA KEV"));
    }

    [Fact]
    public void Nas_example_from_the_specification_is_critical_and_explains_why()
    {
        // NAS: open SMB, outdated software with a CISA KEV vulnerability, critical for the organisation.
        var smb = RiskRules.Evaluate(Svc(445, "microsoft-ds"), Now).Single();
        var result = RiskEngine.ScoreAsset(new AssetRiskInput(AssetType.Nas, AssetCriticality.High, false, false, 6, [smb],
            [Cve("CVE-2017-7494", 9.8, kev: true, epss: 0.94, port: 445, product: "Samba", published: Now.AddYears(-9))], [445]), Now);

        Assert.Equal(RiskLevel.Critical, result.Level);
        Assert.Equal(2, result.Issues.Count);
        Assert.StartsWith("Zaktualizuj Samba", result.Issues[0].Title);
        Assert.Equal(1, result.Issues[0].KnownExploited);
        var kinds = result.Factors.Select(f => f.Kind).ToList();
        Assert.Equal(["top-issue", "more-issues", "criticality", "role", "exposure", "services", "age", "changes"], kinds);
        Assert.Contains(result.Factors, f => f.Kind == "age" && f.Text.Contains("2017"));
    }

    [Fact]
    public void Cves_of_one_product_form_one_remediation_item()
    {
        var result = RiskEngine.ScoreAsset(new AssetRiskInput(AssetType.LinuxHost, AssetCriticality.Medium, false, false, 1, [],
            [Cve("A", 5.0), Cve("B", 7.0), Cve("C", 6.0), Cve("D", 9.0, port: 80, product: "nginx")], []), Now);
        Assert.Equal(2, result.Issues.Count);
        var ssh = result.Issues.Single(i => i.Port == 22);
        Assert.Equal(["B", "C", "A"], ssh.CveIds);
        Assert.Equal(72, ssh.Score); // worst 70 + 2 more CVEs
        Assert.Equal("D", result.Issues[0].CveIds![0]);
    }

    [Fact]
    public void Device_without_issues_is_informational_and_context_never_hides_reasons()
    {
        var quiet = RiskEngine.ScoreAsset(new AssetRiskInput(AssetType.MobileDevice, AssetCriticality.Medium, false, false, 0, [], [], []), Now);
        Assert.Equal((0, RiskLevel.Informational), (quiet.Score, quiet.Level));
        Assert.Contains(quiet.Factors, f => f.Kind == "no-issues");
        Assert.Contains(quiet.Factors, f => f.Kind == "exposure" && f.Text.Contains("nie badano"));

        var router = RiskEngine.ScoreAsset(new AssetRiskInput(AssetType.Router, AssetCriticality.Medium, true, false, 2, [], [], []), Now);
        Assert.Equal(8, router.Score);

        var publicHost = RiskEngine.ScoreAsset(new AssetRiskInput(AssetType.Server, AssetCriticality.Critical, false, true, 1,
            [RiskRules.Evaluate(Svc(23, "telnet"), Now).Single()], [], []), Now);
        Assert.Equal(RiskLevel.Critical, publicHost.Level);   // 70 × 1.3 + 5 (server) + 15 (public)
        Assert.Equal(100, publicHost.Score);
    }

    [Fact]
    public void Levels_and_posture_follow_the_published_thresholds()
    {
        Assert.Equal([RiskLevel.Critical, RiskLevel.High, RiskLevel.Medium, RiskLevel.Low, RiskLevel.Informational],
            new double[] { 80, 60, 35, 15, 14.9 }.Select(RiskEngine.LevelOf));

        Assert.Equal(100, RiskEngine.Posture([]).Score);
        var posture = RiskEngine.Posture([("NAS", 90), ("PC", 20), ("TV", 10)]);
        Assert.Equal(100 - (45 + 0.5 * 40), posture.Score);
        Assert.Equal(1, posture.AssetsByLevel[RiskLevel.Critical]);
        Assert.Contains(posture.Factors, f => f.Text.Contains("NAS"));
        Assert.True(RiskEngine.Posture([("A", 30), ("B", 30)]).Score > posture.Score);
    }
}
