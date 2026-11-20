using System.Globalization;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Weles.App.Reports;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Interfaces;
using Weles.Core.Models;
using Weles.Core.Reports;
using Weles.Core.Risk;
using Weles.Core.Rules;
using Weles.Infrastructure.AI;
using Weles.Infrastructure.Platform;
using Weles.Infrastructure.Queries;
using Weles.Infrastructure.Reports;
using Weles.Infrastructure.Risk;
using Weles.Infrastructure.Scanning;
using Weles.Infrastructure.Settings;
using Weles.Infrastructure.Vulnerabilities;
using Weles.Tests.Support;

namespace Weles.Tests.Reports;

public class ReportTests
{
    private const string Home = "aa:aa:aa:00:00:01";

    private static HostScanResult Host(string ip, string mac, bool gateway, params (int Port, string Service, string? Product, string? Version)[] ports) => new(
        System.Net.IPAddress.Parse(ip), DiscoveryMethod.TcpConnect, null, 64, null, mac, null, gateway,
        new HostClassification(gateway ? AssetType.Router : AssetType.LinuxHost, "Linux", 60, ["test"]),
        ports.Select(p => new PortScanResult(p.Port, "syn-ack", new ServiceProbeResult(
            new ServiceIdentification { ServiceName = p.Service, Product = p.Product, Version = p.Version, Method = "banner", Confidence = 95 }, null))).ToList());

    private sealed class Env : IAsyncDisposable
    {
        public required TestDatabase Db { get; init; }
        public required ScanTarget Target { get; init; }
        public required ScanResultWriter Writer { get; init; }
        public required SettingsService Settings { get; init; }
        public required WelesPaths Paths { get; init; }

        public AuditDocumentBuilder Builder => new(Db, new NetworkQueries(Db, new AssetQueries(Db)), new MonitoringQueries(Db), TimeProvider.System);

        public AuditReportService Reports => new(Db, Paths, TimeProvider.System, NullLogger<AuditReportService>.Instance);

        public async Task<int> ScanAsync(DateTime at, params HostScanResult[] hosts)
        {
            int id;
            await using (var db = Db.CreateDbContext())
            {
                db.Attach(Target);
                var scan = new Scan
                {
                    ScanTarget = Target, Status = ScanStatus.Completed, PortSpecification = "quick", CreatedAt = at, StartedAt = at, CompletedAt = at.AddMinutes(1),
                    ScopeSnapshot = JsonSerializer.Serialize(new[] { new { Value = "10.0.0.0/24", IsExclusion = false }, new { Value = "10.0.0.250", IsExclusion = true } }),
                    NetworkFingerprint = Home, HostsTargeted = 253, HostsAlive = hosts.Length, OpenPorts = hosts.Sum(h => h.OpenPorts.Count)
                };
                db.Scans.Add(scan);
                await db.SaveChangesAsync();
                id = scan.Id;
            }

            foreach (var h in hosts) await Writer.SaveHostAsync(id, h);
            var clock = new Monitoring.MonitoringTests.FixedClock(at.AddMinutes(1).AddSeconds(1));
            await new VulnerabilityMatchingService(Db, clock, NullLogger<VulnerabilityMatchingService>.Instance).RefreshScanAsync(id);
            await new RiskAssessmentService(Db, Settings, clock, NullLogger<RiskAssessmentService>.Instance).RefreshScanAsync(id);
            return id;
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            TempDirectory.Delete(Paths.Root);
        }
    }

    private static async Task<Env> SetupAsync()
    {
        var testDb = await TestDatabase.CreateAsync();
        var target = TestData.ApprovedTarget("Dom");
        await using (var db = testDb.CreateDbContext())
        {
            db.ScanTargets.Add(target);
            await db.SaveChangesAsync();
        }

        var settings = new SettingsService(testDb, TimeProvider.System);
        await new VulnerabilityStore(testDb, settings).UpsertAsync([new Weles.Core.Vulnerabilities.VulnerabilityRecord
        {
            CveId = "CVE-2023-38408", CvssScore = 9.8, Severity = "CRITICAL", Description = "ssh-agent remote code execution",
            AffectedProducts = [new("a", "openbsd", "openssh", VersionEndExcluding: "9.3")]
        }]);
        var paths = WelesPaths.Resolve(TempDirectory.Create());
        paths.EnsureCreated();
        var env = new Env { Db = testDb, Target = target, Writer = new ScanResultWriter(testDb, TimeProvider.System), Settings = settings, Paths = paths };
        await env.Writer.EnsureSegmentsAsync([new SegmentInfo("10.0.0.0/24", "10.0.0.1", Home, "TP-LINK")]);
        return env;
    }

    /// <summary>Two audits of one network: the second adds FTP on the PC and a new device.</summary>
    private static async Task<(Env Env, int First, int Second)> TwoAuditsAsync()
    {
        var env = await SetupAsync();
        var t0 = TestData.Now.AddDays(-2);
        var first = await env.ScanAsync(t0,
            Host("10.0.0.1", Home, true, (80, "http", null, null)),
            Host("10.0.0.5", "aa:aa:aa:00:00:05", false, (22, "ssh", "OpenSSH", "8.9p1")));
        var second = await env.ScanAsync(t0.AddDays(1),
            Host("10.0.0.1", Home, true, (80, "http", null, null)),
            Host("10.0.0.5", "aa:aa:aa:00:00:05", false, (21, "ftp", null, null), (22, "ssh", "OpenSSH", "8.9p1")),
            Host("10.0.0.7", "aa:aa:aa:00:00:07", false, (80, "http", null, null)));
        return (env, first, second);
    }

    [Fact]
    public async Task The_audit_document_describes_the_scan_as_it_was()
    {
        var (env, first, second) = await TwoAuditsAsync();
        await using var _ = env;

        var doc = await env.Builder.BuildAsync(second);
        Assert.NotNull(doc);
        Assert.Equal(AuditDocument.FormatName, doc.Format);
        Assert.Equal(second, doc.Audit.ScanId);
        Assert.Equal("Dom", doc.Audit.ScopeName);
        Assert.Equal(["10.0.0.0/24", "wyklucz 10.0.0.250"], doc.Audit.Scope);
        Assert.Contains("10.0.0.0/24", doc.Audit.Network);
        Assert.Equal(3, doc.Devices.Count);

        var pc = doc.Devices.Single(d => d.Ip == "10.0.0.5");
        Assert.Equal([21, 22], pc.Services.Select(s => s.Port));
        Assert.Equal("OpenSSH", pc.Services.Single(s => s.Port == 22).Product);
        var cve = Assert.Single(pc.Vulnerabilities);
        Assert.Equal("CVE-2023-38408", cve.CveId);
        Assert.Equal(FindingStatus.Open, cve.Status);
        // A configuration finding is part of the audit even without any CVE (the FTP case from a real scan).
        Assert.Contains(pc.Findings, f => f.RuleId == RiskRules.Ftp.Id && f.Port == 21 && f.Evidence is not null);
        Assert.NotNull(pc.RiskScore);
        Assert.True(doc.Devices.Single(d => d.Ip == "10.0.0.1").IsGateway);

        Assert.NotNull(doc.Posture);
        Assert.NotEmpty(doc.Recommendations);
        Assert.Equal(doc.Recommendations.OrderByDescending(r => r.Priority).Select(r => r.Priority), doc.Recommendations.Select(r => r.Priority));
        Assert.Contains(doc.Recommendations, r => r.CveIds.Contains("CVE-2023-38408"));

        var changes = Assert.IsType<AuditChanges>(doc.Changes);
        Assert.Equal(first, changes.PreviousScanId);
        Assert.Contains(changes.Items, c => c.Kind == AuditChangeKind.NewDevice && c.Device.Contains("10.0.0.7"));
        Assert.Contains(changes.Items, c => c.Kind == AuditChangeKind.PortOpened && c.Device.Contains("10.0.0.5"));

        // The first audit stays as it was: no FTP yet, no previous audit to compare with.
        var older = await env.Builder.BuildAsync(first);
        Assert.NotNull(older);
        Assert.Null(older.Changes);
        Assert.Equal(2, older.Devices.Count);
        Assert.DoesNotContain(older.Devices.SelectMany(d => d.Findings), f => f.RuleId == RiskRules.Ftp.Id);
        Assert.Contains(older.Devices.SelectMany(d => d.Vulnerabilities), v => v.CveId == "CVE-2023-38408");

        Assert.Null(await env.Builder.BuildAsync(9999));
    }

    [Fact]
    public async Task An_exported_audit_can_be_opened_on_another_computer()
    {
        var (env, _, second) = await TwoAuditsAsync();
        await using var _e = env;
        var doc = (await env.Builder.BuildAsync(second))!;

        var pdf = AuditPdfRenderer.Render(doc);
        using var zip = new MemoryStream();
        AuditArchive.WriteZip(zip, doc, pdf);
        var saved = await env.Reports.SaveAsync(second, null, ReportFormat.Zip, zip.ToArray());
        Assert.Equal(AuditArchive.Sha256Hex(zip.ToArray()), saved.Sha256);
        Assert.True(saved.Exists);
        var download = await env.Reports.DownloadAsync(saved.Id);
        Assert.NotNull(download);
        Assert.StartsWith(env.Paths.ExportsDirectory, download.Path);
        Assert.Equal("application/zip", download.ContentType);

        using (var archive = new ZipArchive(new MemoryStream(zip.ToArray())))
        {
            Assert.Equal(["manifest.json", "audit.json", "report.pdf"], archive.Entries.Select(e => e.FullName));
        }

        // "Another computer": a fresh database imports the file.
        await using var other = await SetupAsync();
        zip.Position = 0;
        var imported = await other.Reports.ImportAsync(zip, "audyt.zip");
        Assert.Equal(second, imported.OriginalScanId);
        Assert.Equal(3, imported.DeviceCount);
        var opened = await other.Reports.ImportedDocumentAsync(imported.Id);
        Assert.NotNull(opened);
        Assert.Equal(JsonSerializer.Serialize(doc, AuditJson.Options), JsonSerializer.Serialize(opened.Value.Document, AuditJson.Options));

        // The same audit is not imported twice – neither as ZIP nor as the bare JSON.
        zip.Position = 0;
        await Assert.ThrowsAsync<AuditImportException>(() => other.Reports.ImportAsync(zip, "audyt.zip"));
        await Assert.ThrowsAsync<AuditImportException>(() => other.Reports.ImportAsync(new MemoryStream(AuditArchive.ToJson(doc)), "audit.json"));

        // Imported audits never enter the local inventory.
        await using (var db = other.Db.CreateDbContext())
        {
            Assert.Equal(0, db.Assets.Count());
            Assert.Equal(0, db.Scans.Count());
        }

        // A PDF of the imported audit is stored as its file; deleting the audit removes it.
        var importedPdf = await other.Reports.SaveAsync(null, imported.Id, ReportFormat.Pdf, AuditPdfRenderer.Render(opened.Value.Document, imported: true), "pl");
        Assert.StartsWith(other.Paths.ReportsDirectory, (await other.Reports.DownloadAsync(importedPdf.Id))!.Path);
        Assert.True(await other.Reports.DeleteImportedAsync(imported.Id));
        Assert.Empty(await other.Reports.ImportedAsync());
        Assert.Empty(await other.Reports.ReportsAsync());
        Assert.False(File.Exists(Path.Combine(other.Paths.ReportsDirectory, importedPdf.FileName)));
    }

    private static AuditDocument Sample() => new(AuditDocument.FormatName, AuditDocument.CurrentSchemaVersion, TestData.Now, "WELES test",
        new AuditInfo(7, "LAN", ["192.168.1.0/24"], "192.168.1.0/24 – router", false, TestData.Now, TestData.Now.AddMinutes(2), "quick", ScanTrigger.Manual, 254, 1, 1, false),
        new AuditPosture(72, 70, [new RiskFactor("worst", "najbardziej zagrożone urządzenie", -28)]),
        [new AuditDevice("NAS", "192.168.1.10", null, null, "Synology", AssetType.Nas, "Linux", null, AssetCriticality.High, false, 28, RiskLevel.Low, [],
            [new AuditService(21, TransportProtocol.Tcp, "ftp", null, null, 60, false, null)], [],
            [new AuditFinding("FTP-CLEARTEXT", "FTP bez szyfrowania", RiskLevel.Medium, 45, 21, "Port 21: FTP", "Wyłącz FTP", FindingStatus.Open)])],
        [new AuditRecommendation("NAS", "192.168.1.10", "FTP bez szyfrowania", 50, RiskLevel.Medium, 21, "Wyłącz FTP", [], 0)],
        null,
        new AuditAiSummaryInfo("### Ogólna ocena\n- **FTP** na NAS bez szyfrowania", "qwen", "pl", TestData.Now));

    private static async Task<string> ImportErrorAsync(byte[] data, string name)
    {
        var ex = await Assert.ThrowsAsync<AuditImportException>(() => AuditArchive.ReadAsync(new MemoryStream(data), name));
        return ex.Message;
    }

    private static byte[] Zip(params (string Name, byte[] Data)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, data) in entries)
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(data);
            }
        }

        return ms.ToArray();
    }

    private static byte[] Mutate(Action<JsonObject> change)
    {
        var node = JsonNode.Parse(AuditArchive.ToJson(Sample()))!.AsObject();
        change(node);
        return Encoding.UTF8.GetBytes(node.ToJsonString());
    }

    [Fact]
    public async Task Imported_files_are_validated_before_anything_is_stored()
    {
        using var valid = new MemoryStream();
        AuditArchive.WriteZip(valid, Sample(), null);
        var ok = await AuditArchive.ReadAsync(new MemoryStream(valid.ToArray()), "a.zip");
        Assert.Equal("NAS", ok.Document.Devices[0].Name);

        byte[] Entry(string name)
        {
            using var zip = new ZipArchive(new MemoryStream(valid.ToArray()));
            using var s = zip.GetEntry(name)!.Open();
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            return ms.ToArray();
        }

        var manifest = Entry("manifest.json");
        var json = Entry("audit.json");

        // Changed content no longer matches the manifest.
        var tampered = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(json).Replace("192.168.1.10", "192.168.1.66"));
        Assert.Contains("Suma kontrolna", await ImportErrorAsync(Zip(("manifest.json", manifest), ("audit.json", tampered)), "a.zip"));
        // Path traversal and unknown files are refused – nothing is ever extracted.
        Assert.Contains("Nieoczekiwany plik", await ImportErrorAsync(Zip(("manifest.json", manifest), ("audit.json", json), ("../../.bashrc", [1])), "a.zip"));
        Assert.Contains("Nieoczekiwany plik", await ImportErrorAsync(Zip(("manifest.json", manifest), ("data/audit.json", json)), "a.zip"));
        Assert.Contains("brakuje", await ImportErrorAsync(Zip(("audit.json", json)), "a.zip"));
        // An entry larger than its limit (here: a 1 MB "manifest" of zeros – compresses to almost nothing).
        Assert.Contains("za duży", await ImportErrorAsync(Zip(("manifest.json", new byte[1024 * 1024]), ("audit.json", json)), "a.zip"));
        Assert.Contains("nie jest archiwum ZIP", await ImportErrorAsync([1, 2, 3, 4], "a.zip"));
        Assert.Contains("uszkodzone", await ImportErrorAsync([(byte)'P', (byte)'K', 3, 4, 0, 0, 0], "a.zip"));

        Assert.Contains("format", await ImportErrorAsync(Mutate(n => n["format"] = "something-else"), "a.json"));
        Assert.Contains("Wersja formatu 99", await ImportErrorAsync(Mutate(n => n["schemaVersion"] = 99), "a.json"));
        Assert.Contains("niekompletny", await ImportErrorAsync(Mutate(n => n.Remove("devices")), "a.json"));
        Assert.Contains("0–100", await ImportErrorAsync(Mutate(n => n["devices"]![0]!["riskScore"] = 500), "a.json"));
        Assert.Contains("JSON", await ImportErrorAsync(Encoding.UTF8.GetBytes("{\"format\": "), "a.json"));
        Assert.Contains("zbyt długi tekst", await ImportErrorAsync(Mutate(n => n["devices"]![0]!["name"] = new string('x', 30_000)), "a.json"));
        var deep = string.Concat(Enumerable.Repeat("{\"a\":", 100)) + "1" + new string('}', 100);
        Assert.Contains("JSON", await ImportErrorAsync(Encoding.UTF8.GetBytes(deep), "a.json"));

        // A bare JSON export is accepted as well.
        Assert.Equal(7, (await AuditArchive.ReadAsync(new MemoryStream(json), "audit.json")).Document.Audit.ScanId);
    }

    [Fact]
    public void The_pdf_report_renders_in_both_languages()
    {
        var culture = CultureInfo.CurrentCulture;
        var ui = CultureInfo.CurrentUICulture;
        try
        {
            foreach (var language in new[] { "pl-PL", "en-GB" })
            {
                CultureInfo.CurrentCulture = CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(language);
                var pdf = AuditPdfRenderer.Render(Sample());
                Assert.True(pdf.Length > 2000);
                Assert.Equal("%PDF", Encoding.ASCII.GetString(pdf, 0, 4));
                Assert.Equal("%PDF", Encoding.ASCII.GetString(AuditPdfRenderer.Render(Sample() with { AiSummary = null, Devices = [], Recommendations = [] }, imported: true), 0, 4));
            }
        }
        finally
        {
            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = ui;
        }
    }

    private sealed class FakeModel(bool fail, params string[] answer) : IAiService
    {
        public List<IReadOnlyList<AiChatMessage>> Requests { get; } = [];

        public Task<AiEngineStatus> GetStatusAsync(CancellationToken ct = default) =>
            Task.FromResult(new AiEngineStatus(AiEngineState.Ready, "fake", "", "m", null, ["m"], null));

        public async IAsyncEnumerable<AiChatChunk> ChatAsync(IReadOnlyList<AiChatMessage> messages, [EnumeratorCancellation] CancellationToken ct = default)
        {
            Requests.Add(messages);
            await Task.Yield();
            if (fail) throw new HttpRequestException("connection refused");
            foreach (var part in answer) yield return new AiChatChunk(part);
            yield return new AiChatChunk("", Done: true, AnswerTokens: 10);
        }
    }

    [Fact]
    public async Task The_ai_summary_is_made_from_the_audit_data_and_goes_into_the_report()
    {
        var (env, _, second) = await TwoAuditsAsync();
        await using var _e = env;
        var options = Options.Create(new AiOptions { Model = "qwen-test" });

        var broken = new FakeModel(fail: true);
        var events = await new AuditSummaryService(broken, env.Builder, env.Reports, options, NullLogger<AuditSummaryService>.Instance).GenerateAsync(second, "pl").ToListAsync();
        Assert.NotNull(Assert.IsType<SummaryFinished>(events[^1]).Error);
        Assert.Null(await env.Reports.AiSummaryAsync(second));

        var model = new FakeModel(false, "### Ogólna ocena\n", "Sieć wymaga uwagi: OpenSSH na 10.0.0.5.");
        events = await new AuditSummaryService(model, env.Builder, env.Reports, options, NullLogger<AuditSummaryService>.Instance).GenerateAsync(second, "pl").ToListAsync();
        var finished = Assert.IsType<SummaryFinished>(events[^1]);
        Assert.Null(finished.Error);

        var data = model.Requests.Single()[1].Content;
        Assert.StartsWith("DANE", data);
        Assert.Contains("10.0.0.5", data);
        Assert.Contains("CVE-2023-38408", data);
        Assert.Contains("FTP bez szyfrowania", data);
        Assert.Contains("POPRZEDNI AUDYT tej sieci: skan #", data);
        Assert.DoesNotContain("PIERWSZY AUDYT", data);
        Assert.DoesNotContain(data, c => char.IsControl(c) && c is not '\n' and not '\r');

        var doc = await env.Builder.BuildAsync(second);
        Assert.Equal("qwen-test", doc!.AiSummary!.Model);
        Assert.Contains("OpenSSH", doc.AiSummary.Text);
        Assert.True((await env.Reports.AuditsAsync()).Single(a => a.ScanId == second).HasAiSummary);

        await env.Reports.DeleteAiSummaryAsync(second);
        Assert.Null((await env.Builder.BuildAsync(second))!.AiSummary);
    }
}
