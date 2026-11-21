using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Integrations;
using Weles.Core.Models;
using Weles.Core.Rules;
using Weles.Core.Risk;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Integrations;
using Weles.Infrastructure.Queries;
using Weles.Infrastructure.Risk;
using Weles.Infrastructure.Scanning;
using Weles.Infrastructure.Settings;
using Weles.Infrastructure.Vulnerabilities;
using Weles.Tests.Support;

namespace Weles.Tests.Integrations;

public class DefectDojoTests
{
    private const string Router = "aa:aa:aa:00:00:01";

    /// <summary>Reversible stand-in for Data Protection – enough to see that the plain key is never stored.</summary>
    private sealed class FakeProtector : ISecretProtector
    {
        public string Protect(string plaintext) => "enc:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));
        public string? Unprotect(string protectedText) => protectedText.StartsWith("enc:") ? Encoding.UTF8.GetString(Convert.FromBase64String(protectedText[4..])) : null;
    }

    /// <summary>A fake DefectDojo API: records requests and answers like the real one.</summary>
    private sealed class FakeDojo(HttpStatusCode status = HttpStatusCode.Created) : HttpMessageHandler
    {
        public List<(HttpRequestMessage Request, string Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            Requests.Add((request, body));
            var json = request.RequestUri!.AbsolutePath.EndsWith("/reimport-scan/") ? """{"test": 12, "engagement": 3, "product": 2, "statistics": {}}""" : """{"count": 0, "results": []}""";
            return new HttpResponseMessage(request.Method == HttpMethod.Get && status == HttpStatusCode.Created ? HttpStatusCode.OK : status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }
    }

    private static HostScanResult Host(string ip, string mac, params (int Port, string Service, string? Product, string? Version)[] ports) => new(
        IPAddress.Parse(ip), DiscoveryMethod.TcpConnect, null, 64, null, mac, null, false, new HostClassification(AssetType.LinuxHost, "Linux", 60, ["test"]),
        ports.Select(p => new PortScanResult(p.Port, "syn-ack", new ServiceProbeResult(new ServiceIdentification { ServiceName = p.Service, Product = p.Product, Version = p.Version, Method = "banner", Confidence = 95 }, null))).ToList());

    private static async Task<(TestDatabase Db, DefectDojoService Dojo, SettingsService Settings, FakeDojo Server)> SetupAsync(HttpStatusCode status = HttpStatusCode.Created)
    {
        var db = await TestDatabase.CreateAsync();
        var settings = new SettingsService(db, TimeProvider.System);
        await new VulnerabilityStore(db, settings).UpsertAsync([new Weles.Core.Vulnerabilities.VulnerabilityRecord
        {
            CveId = "CVE-2023-38408", CvssScore = 9.8, CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Severity = "CRITICAL", Description = "ssh-agent remote code execution",
            Weaknesses = ["CWE-428"], AffectedProducts = [new("a", "openbsd", "openssh", VersionEndExcluding: "9.3")]
        }]);
        var target = TestData.ApprovedTarget();
        int scanId;
        await using (var ctx = db.CreateDbContext())
        {
            var scan = TestData.CompletedScan(target, TestData.Now);
            scan.NetworkFingerprint = Router;
            ctx.Scans.Add(scan);
            await ctx.SaveChangesAsync();
            scanId = scan.Id;
        }

        var writer = new ScanResultWriter(db, TimeProvider.System);
        await writer.SaveHostAsync(scanId, Host("192.168.1.10", "aa:aa:aa:00:00:10", (21, "ftp", null, null), (22, "ssh", "OpenSSH", "8.9p1")));
        await writer.SaveHostAsync(scanId, Host("192.168.1.11", "aa:aa:aa:00:00:11", (22, "ssh", "OpenSSH", "8.9p1")));
        await new VulnerabilityMatchingService(db, TimeProvider.System, NullLogger<VulnerabilityMatchingService>.Instance).RefreshScanAsync(scanId);
        await new RiskAssessmentService(db, settings, TimeProvider.System, NullLogger<RiskAssessmentService>.Instance).RefreshScanAsync(scanId);

        var server = new FakeDojo(status);
        var dojo = new DefectDojoService(db, settings, new NetworkQueries(db, new AssetQueries(db)), new WebQueries(db), new FakeProtector(), TimeProvider.System,
            NullLogger<DefectDojoService>.Instance, _ => server);
        return (db, dojo, settings, server);
    }

    [Fact]
    public async Task Findings_carry_cve_cwe_cvss_and_follow_the_chosen_granularity()
    {
        var (db, dojo, _, _) = await SetupAsync();
        await using var _db = db;

        var report = await dojo.BuildAsync(new DojoExportOptions());
        var cves = report.Findings.Where(f => f.Cve == "CVE-2023-38408").ToList();
        Assert.Equal(2, cves.Count);                                    // per endpoint: one per host
        var cve = cves[0];
        Assert.Equal(("Critical", 428, 9.8), (cve.Severity, cve.Cwe, cve.CvssScore));
        Assert.Equal(["CVE-2023-38408"], cve.VulnerabilityIds);
        Assert.StartsWith("CVSS:3.1/", cve.CvssVector);
        Assert.Equal(("OpenSSH", "8.9p1"), (cve.ComponentName, cve.ComponentVersion));
        Assert.Single(cve.Endpoints);
        Assert.Equal(22, cve.Endpoints[0].Port);
        Assert.Contains("nvd.nist.gov/vuln/detail/CVE-2023-38408", cve.References);
        var ftp = Assert.Single(report.Findings, f => f.VulnIdFromTool == RiskRules.Ftp.Id);
        Assert.Equal(319, ftp.Cwe);                                    // configuration findings have a CWE too
        Assert.Equal(21, ftp.Endpoints.Single().Port);

        // Stable ids: a second build produces the same ones (re-import updates instead of duplicating).
        Assert.Equal(report.Findings.Select(f => f.UniqueId).Order(), (await dojo.BuildAsync(new DojoExportOptions())).Findings.Select(f => f.UniqueId).Order());

        // Per issue: one CVE finding with both hosts as endpoints.
        var grouped = await dojo.BuildAsync(new DojoExportOptions(Grouping: DojoGrouping.PerIssue));
        var one = Assert.Single(grouped.Findings, f => f.Cve == "CVE-2023-38408");
        Assert.Equal(["192.168.1.10", "192.168.1.11"], one.Endpoints.Select(e => e.Host).Order());

        // Filters: severity threshold, only configuration, services as inventory.
        Assert.All((await dojo.BuildAsync(new DojoExportOptions(MinimumSeverity: DojoSeverity.Critical))).Findings, f => Assert.Equal("Critical", f.Severity));
        Assert.DoesNotContain((await dojo.BuildAsync(new DojoExportOptions(IncludeCves: false))).Findings, f => f.Cve is not null);
        Assert.Equal(3, (await dojo.BuildAsync(new DojoExportOptions(IncludeCves: false, IncludeConfiguration: false, IncludeWeb: false, IncludeServices: true))).Findings.Count);
        Assert.Empty((await dojo.BuildAsync(new DojoExportOptions(MinimumMatch: VulnerabilityMatchStatus.Confirmed, IncludeConfiguration: false, IncludeWeb: false)))
            .Findings.Where(f => f.Cve is not null && !f.Verified));

        // Only fields of DefectDojo's Finding model (unknown fields make DefectDojo's generic import fail).
        string[] allowed = ["title", "severity", "description", "mitigation", "impact", "references", "date", "cwe", "cve", "vulnerability_ids", "cvssv3", "cvssv3_score",
            "epss_score", "epss_percentile", "component_name", "component_version", "service", "unique_id_from_tool", "vuln_id_from_tool", "active", "verified",
            "static_finding", "dynamic_finding", "endpoints"];
        using var json = JsonDocument.Parse(DefectDojoService.Serialize(report));
        foreach (var finding in json.RootElement.GetProperty("findings").EnumerateArray())
        {
            Assert.All(finding.EnumerateObject(), p => Assert.Contains(p.Name, allowed));
        }
    }

    [Fact]
    public async Task Sending_reimports_into_the_configured_test_with_the_encrypted_key()
    {
        var (db, dojo, settings, server) = await SetupAsync();
        await using var _db = db;

        Assert.NotEmpty(await dojo.SaveAsync(new DojoConnection("http://dojo.example.com"), "k", new DojoExportOptions())); // plain http to a public host
        Assert.NotEmpty(await dojo.SaveAsync(new DojoConnection("https://user:pass@dojo.example.com"), "k", new DojoExportOptions()));
        Assert.Empty(await dojo.SaveAsync(new DojoConnection("http://192.168.1.50:8080/", Product: "AGH", Engagement: "Discovery"), "secret-key-123", new DojoExportOptions()));
        var stored = await settings.GetAsync("dojo.apiKey");
        Assert.DoesNotContain("secret-key-123", stored);

        Assert.True((await dojo.TestConnectionAsync()).Success);
        var result = await dojo.SendAsync(new DojoExportOptions());
        Assert.True(result.Success, result.Message);
        Assert.Equal(12, result.TestId);

        var (request, body) = server.Requests.Last();
        Assert.Equal("http://192.168.1.50:8080/api/v2/reimport-scan/", request.RequestUri!.ToString());
        Assert.Equal(("Token", "secret-key-123"), (request.Headers.Authorization!.Scheme, request.Headers.Authorization.Parameter));
        foreach (var field in (string[])["Generic Findings Import", "AGH", "Discovery", "WELES discovery", "auto_create_context", "close_old_findings"]) Assert.Contains(field, body);
        Assert.Contains("CVE-2023-38408", body);
        Assert.True((await dojo.SettingsAsync()).LastResult!.Success);
    }

    [Fact]
    public async Task A_rejected_key_is_reported()
    {
        var (db, dojo, _, _) = await SetupAsync(HttpStatusCode.Unauthorized);
        await using var _db = db;
        await dojo.SaveAsync(new DojoConnection("https://dojo.lab"), "bad", new DojoExportOptions());
        Assert.Contains("401", (await dojo.TestConnectionAsync()).Message);
        Assert.False((await dojo.SendAsync(new DojoExportOptions())).Success);
    }
}
