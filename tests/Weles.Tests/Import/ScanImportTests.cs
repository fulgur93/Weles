using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Weles.Core.Enums;
using Weles.Core.Import;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Fingerprint;
using Weles.Infrastructure.Import;
using Weles.Infrastructure.Queries;
using Weles.Infrastructure.Risk;
using Weles.Infrastructure.Scanning;
using Weles.Infrastructure.Settings;
using Weles.Infrastructure.Vulnerabilities;
using Weles.Tests.Support;

namespace Weles.Tests.Import;

public class ScanImportTests
{
    private const string Nmap = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE nmaprun>
        <?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>
        <nmaprun scanner="nmap" args="nmap -sV -oX - 10.0.0.0/24" start="1763700000" version="7.94">
          <host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><address addr="AA:BB:CC:00:00:05" addrtype="mac" vendor="Dell"/>
            <hostnames><hostname name="web01.lab"/></hostnames>
            <ports>
              <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu 3ubuntu0.10" conf="10"><cpe>cpe:/a:openbsd:openssh:8.9p1</cpe></service></port>
              <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24.0" conf="10"/></port>
              <port protocol="tcp" portid="81"><state state="closed"/></port>
            </ports></host>
          <host><status state="down"/><address addr="10.0.0.6" addrtype="ipv4"/></host>
          <host><status state="up"/><address addr="192.168.99.9" addrtype="ipv4"/><ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports></host>
        </nmaprun>
        """;

    private sealed class Env : IAsyncDisposable
    {
        public required TestDatabase Db { get; init; }
        public required ScanImportService Importer { get; init; }
        public required ScanTargetService Targets { get; init; }
        public ValueTask DisposeAsync() => Db.DisposeAsync();
    }

    private static async Task<Env> SetupAsync()
    {
        var db = await TestDatabase.CreateAsync();
        var settings = new SettingsService(db, TimeProvider.System);
        await new VulnerabilityStore(db, settings).UpsertAsync([new Weles.Core.Vulnerabilities.VulnerabilityRecord
        {
            CveId = "CVE-2023-38408", CvssScore = 9.8, Severity = "CRITICAL", Description = "ssh-agent", AffectedProducts = [new("a", "openbsd", "openssh", VersionEndExcluding: "9.3")]
        }]);
        var writer = new ScanResultWriter(db, TimeProvider.System);
        var post = new ScanPostProcessor(new SignatureService(db, TimeProvider.System, NullLogger<SignatureService>.Instance),
            new VulnerabilityMatchingService(db, TimeProvider.System, NullLogger<VulnerabilityMatchingService>.Instance),
            new RiskAssessmentService(db, settings, TimeProvider.System, NullLogger<RiskAssessmentService>.Instance), db, TimeProvider.System, NullLogger<ScanPostProcessor>.Instance);
        return new Env
        {
            Db = db, Importer = new ScanImportService(db, writer, post, new OuiDatabase(), TimeProvider.System, NullLogger<ScanImportService>.Instance),
            Targets = new ScanTargetService(db, new ScanCoordinator(TimeProvider.System), Microsoft.Extensions.Options.Options.Create(new ScanOptions()), TimeProvider.System, NullLogger<ScanTargetService>.Instance)
        };
    }

    private static Stream Text(string s) => new MemoryStream(Encoding.UTF8.GetBytes(s));

    [Fact]
    public async Task Nmap_xml_is_imported_into_a_scope_safely()
    {
        await using var env = await SetupAsync();
        var scope = (await env.Targets.CreateAsync(new ScanTargetInput("Lab", null, "10.0.0.0/24", null, false))).Id!.Value;

        var result = await env.Importer.ImportAsync(Text(Nmap), "lab.xml", scope);
        Assert.Equal("nmap XML", result.Format);
        Assert.Equal(1, result.Hosts);          // the down host is not imported, the one outside the scope is dropped
        Assert.Equal(2, result.Ports);          // the closed port is not imported
        Assert.Contains(result.Warnings, w => w.Contains("spoza zakresu"));

        await using var db = env.Db.CreateDbContext();
        var scan = await db.Scans.SingleAsync(s => s.Id == result.ScanId);
        Assert.Equal((ScanStatus.Completed, ScanTrigger.Import), (scan.Status, scan.Trigger));
        Assert.Equal(new DateTime(2025, 11, 21, 4, 40, 0, DateTimeKind.Utc), scan.StartedAt);
        var host = await db.DiscoveredHosts.Include(h => h.Ports).ThenInclude(p => p.Service).Include(h => h.Asset).SingleAsync(h => h.ScanId == scan.Id);
        Assert.Equal(("10.0.0.5", "web01.lab", "aa:bb:cc:00:00:05"), (host.IpAddress, host.Hostname, host.MacAddress));
        var ssh = host.Ports.Single(p => p.Port == 22).Service!;
        Assert.Equal(("OpenSSH", "8.9p1", "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"), (ssh.Product, ssh.Version, ssh.Cpe));
        // Imported versions go through vulnerability matching like scanned ones.
        Assert.True(await db.AssetVulnerabilities.AnyAsync(v => v.AssetId == host.AssetId && v.Vulnerability!.CveId == "CVE-2023-38408"));
    }

    [Fact]
    public async Task An_xml_external_entity_cannot_read_files()
    {
        await using var env = await SetupAsync();
        var xxe = """<?xml version="1.0"?><!DOCTYPE nmaprun [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><hostnames><hostname name="&xxe;"/></hostnames></host></nmaprun>""";
        var ex = await Assert.ThrowsAsync<ScanImportException>(() => env.Importer.ImportAsync(Text(xxe), "xxe.xml", null));
        Assert.DoesNotContain("root:", ex.Message);
        await using var db = env.Db.CreateDbContext();
        Assert.False(await db.DiscoveredHosts.AnyAsync());
    }

    [Fact]
    public async Task Csv_and_json_round_trip_and_two_imports_show_changes()
    {
        await using var env = await SetupAsync();
        const string csv = "ip,port,protocol,service,product,version,hostname\n10.1.0.10,22,tcp,ssh,OpenSSH,9.6p1,a.lab\n10.1.0.10,80,tcp,http,nginx,1.24.0,a.lab\n10.1.0.11,443,tcp,https,,,b.lab\nnot-an-ip,1,tcp,,,,\n";
        var first = await env.Importer.ImportAsync(Text(csv), "runda1.csv", null);
        Assert.Equal(("CSV", 2, 3, 1), (first.Format, first.Hosts, first.Ports, first.Skipped));

        // Second run: 10.1.0.11 gone, a new port on .10 (JSON, the WELES export format), into the scope created by the first import.
        const string json = """{ "format": "weles-scan-results", "hosts": [ { "ip": "10.1.0.10", "hostname": "a.lab", "ports": [ { "port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1" }, { "port": 80, "service": "http", "product": "nginx", "version": "1.24.0" }, { "port": 8080, "service": "http" } ] } ] }""";
        var second = await env.Importer.ImportAsync(Text(json), "runda2.json", first.ScopeId);
        Assert.Equal(("JSON", 1, 3), (second.Format, second.Hosts, second.Ports));

        var monitoring = new MonitoringQueries(env.Db);
        var diff = await monitoring.CompareAsync(first.ScanId, second.ScanId);
        Assert.NotNull(diff);
        Assert.True(diff.SameNetwork);
        Assert.Contains(diff.MissingDevices, d => d.Ip == "10.1.0.11");
        Assert.Contains(diff.Changed.SelectMany(c => c.Changes), c => c.Kind == AssetChangeKind.PortOpened && c.Port == 8080);

        Assert.Equal(["10.1.0.10", "a.lab", "", "", "22", "tcp", "ssh", "OpenSSH", "9.6p1"], ScanImportService.SplitCsv("10.1.0.10,a.lab,,,22,tcp,ssh,OpenSSH,9.6p1"));
        Assert.Equal(["=1+1"], ScanImportService.SplitCsv("'=1+1"));   // the export's CSV-injection guard is undone on import
    }

    [Fact]
    public async Task Invalid_files_are_refused_with_a_reason()
    {
        await using var env = await SetupAsync();
        await Assert.ThrowsAsync<ScanImportException>(() => env.Importer.ImportAsync(Text("<html></html>"), "x.xml", null));
        await Assert.ThrowsAsync<ScanImportException>(() => env.Importer.ImportAsync(Text("{ broken"), "x.json", null));
        await Assert.ThrowsAsync<ScanImportException>(() => env.Importer.ImportAsync(Text("port,service\n22,ssh"), "x.csv", null));
        await Assert.ThrowsAsync<ScanImportException>(() => env.Importer.ImportAsync(new MemoryStream(new byte[ScanImportService.MaxFileBytes + 1]), "big.csv", null));
    }

    [Fact]
    public void Targets_are_read_from_csv_and_json()
    {
        var csv = TargetImport.Parse("target,exclude\n10.0.0.0/24\n10.0.0.1,yes\n# komentarz\nwww.firma.pl\n", "cele.csv");
        Assert.Equal(["10.0.0.0/24", "www.firma.pl"], csv.Includes);
        Assert.Equal(["10.0.0.1"], csv.Excludes);
        var json = TargetImport.Parse("""{ "targets": ["10.0.0.0/24", { "ip": "10.0.1.5" }], "exclude": ["10.0.0.9"] }""", "cele.json");
        Assert.Equal(["10.0.0.0/24", "10.0.1.5"], json.Includes);
        Assert.Equal(["10.0.0.9"], json.Excludes);
        Assert.NotEmpty(TargetImport.Parse("[ {} ]", "x.json").Errors);
    }
}
