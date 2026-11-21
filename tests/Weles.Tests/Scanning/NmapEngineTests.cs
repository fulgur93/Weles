using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Models;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Import;
using Weles.Infrastructure.Scanning;
using Weles.Tests.Support;

namespace Weles.Tests.Scanning;

/// <summary>Nmap as an optional engine – exercised with a stand-in program that prints nmap XML and records its arguments.</summary>
public class NmapEngineTests
{
    /// <summary>A fake "nmap": --version, then for each target in -iL reports the given ports open as nginx 1.18.0.</summary>
    private static string FakeNmap(string dir, params int[] openPorts)
    {
        var script = Path.Combine(dir, "nmap");
        var ports = string.Join(' ', openPorts);
        File.WriteAllText(script, $$"""
            #!/bin/bash
            if [ "$1" = "--version" ]; then echo "Nmap version 7.94SVN ( https://nmap.org )"; exit 0; fi
            printf '%s\n' "$@" > "{{dir}}/args.txt"
            while [ $# -gt 0 ]; do case "$1" in -iL) targets="$2"; shift;; esac; shift; done
            cp "$targets" "{{dir}}/targets.txt"
            echo '<?xml version="1.0"?><nmaprun scanner="nmap" start="1763740000">'
            while read -r ip; do
              echo "<host><status state=\"up\"/><address addr=\"$ip\" addrtype=\"ipv4\"/><ports>"
              for p in {{ports}}; do
                echo "<port protocol=\"tcp\" portid=\"$p\"><state state=\"open\"/><service name=\"http\" product=\"nginx\" version=\"1.18.0\" conf=\"10\"><cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe></service></port>"
              done
              echo "</ports></host>"
            done < "$targets"
            echo "<host><status state=\"up\"/><address addr=\"10.66.66.66\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/></port></ports></host>"
            echo '</nmaprun>'
            """.Replace("\r", ""));
        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return script;
    }

    private static async Task<(TestDatabase Db, int ScanId)> ScanAsync(string? nmapPath, string ports)
    {
        var db = await TestDatabase.CreateAsync();
        var scanOptions = new ScanOptions { UseIcmp = false, UseMdns = false, ConnectTimeoutMs = 800, BannerTimeoutMs = 600, ProbeTimeoutMs = 1500, LivenessPorts = [1], NmapPath = nmapPath };
        var opts = Options.Create(scanOptions);
        var oui = new OuiDatabase();
        var coordinator = new ScanCoordinator(TimeProvider.System);
        var nmap = new NmapEngine(opts, NullLogger<NmapEngine>.Instance);
        var engine = new ScanEngine(db, new ScanResultWriter(db, TimeProvider.System), oui, new LocalNetworkDiscovery(oui), opts, TimeProvider.System, NullLogger<ScanEngine>.Instance, nmap);
        var targets = new ScanTargetService(db, coordinator, opts, TimeProvider.System, NullLogger<ScanTargetService>.Instance);
        var created = await targets.CreateAsync(new ScanTargetInput("Loopback", null, "127.0.0.1", null, false));
        Assert.True((await targets.ApproveAsync(created.Id!.Value, confirmedAuthorization: true)).Success);
        var started = await targets.StartScanAsync(created.Id!.Value, ports, engine: PortEngine.Nmap);
        await engine.RunAsync(started.Id!.Value, coordinator.GetProgress(started.Id!.Value)!, CancellationToken.None);
        return (db, started.Id!.Value);
    }

    [Fact]
    public async Task Nmap_finds_ports_and_versions_while_weles_keeps_its_own_identification()
    {
        if (OperatingSystem.IsWindows()) return;
        var dir = Directory.CreateTempSubdirectory("weles-nmap-").FullName;
        await using var silent = new FakeServer(async (_, ct) => await Task.Delay(5000, ct));                   // says nothing – WELES can only guess
        await using var apache = FakeServer.Http("HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n<title>Intranet</title>");
        var probe = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        probe.Start();
        var closedPort = ((System.Net.IPEndPoint)probe.LocalEndpoint).Port;   // free port, nothing listening
        probe.Stop();

        var (db, scanId) = await ScanAsync(FakeNmap(dir, silent.Port, apache.Port), $"{silent.Port},{apache.Port},{closedPort}");
        await using (db)
        {
            await using var ctx = db.CreateDbContext();
            var scan = await ctx.Scans.Include(s => s.Events).SingleAsync(s => s.Id == scanId);
            Assert.Equal((ScanStatus.Completed, PortEngine.Nmap), (scan.Status, scan.Engine));
            Assert.Contains(scan.Events, e => e.Message.StartsWith("Silnik portów i wersji: nmap 7.94SVN"));
            Assert.Contains(scan.Events, e => e.Message.StartsWith("nmap 7.94SVN: 1 hostów, 2 otwartych portów"));
            Assert.Contains("7.94SVN", scan.SettingsJson);

            var ports = await ctx.DiscoveredPorts.Include(p => p.Service).Where(p => p.Host!.ScanId == scanId).ToDictionaryAsync(p => p.Port);
            Assert.Equal(2, ports.Count);                                       // only what nmap reported open; the scope's host only
            Assert.DoesNotContain(closedPort, ports.Keys);
            Assert.Equal(1, await ctx.DiscoveredHosts.CountAsync(h => h.ScanId == scanId)); // 10.66.66.66 from the output is ignored

            var guessed = ports[silent.Port].Service!;
            Assert.Equal(("nginx", "1.18.0"), (guessed.Product, guessed.Version));
            Assert.EndsWith("+nmap", guessed.DetectionMethod);
            var own = ports[apache.Port].Service!;
            Assert.Equal("Apache httpd", own.Product);                         // WELES's own answer from the banner wins
        }

        // Safe options only: TCP connect, version detection, no scripts, no OS detection, targets from a file.
        var args = File.ReadAllLines(Path.Combine(dir, "args.txt"));
        Assert.Contains("-sT", args);
        Assert.Contains("-sV", args);
        Assert.Contains("-Pn", args);
        Assert.DoesNotContain(args, a => NmapEngine.Forbidden.Contains(a) || a.StartsWith("--script", StringComparison.Ordinal));
        Assert.Equal(["127.0.0.1"], File.ReadAllLines(Path.Combine(dir, "targets.txt")));
        Assert.False(File.Exists(args[Array.IndexOf(args, "-iL") + 1]));    // temporary target file removed
    }

    [Fact]
    public async Task Without_nmap_the_built_in_engine_scans()
    {
        await using var ssh = FakeServer.Banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n");
        var (db, scanId) = await ScanAsync(Path.Combine(Path.GetTempPath(), "no-such-nmap-" + Guid.NewGuid()), $"{ssh.Port}");
        await using (db)
        {
            await using var ctx = db.CreateDbContext();
            var scan = await ctx.Scans.Include(s => s.Events).SingleAsync(s => s.Id == scanId);
            Assert.Equal(ScanStatus.Completed, scan.Status);
            Assert.Contains(scan.Events, e => e.Message.Contains("nie jest zainstalowany"));
            var port = await ctx.DiscoveredPorts.Include(p => p.Service).SingleAsync(p => p.Host!.ScanId == scanId);
            Assert.Equal("OpenSSH", port.Service!.Product);
        }
    }

    [Fact]
    public void Arguments_and_identification_merge()
    {
        Assert.Equal("22,80-82,443", NmapEngine.CompressPorts([443, 80, 81, 82, 22, 80, 0, 70000]));
        var args = NmapEngine.Arguments("/tmp/t.txt", [22, 80], new ScanOptions { ConnectionsPerSecond = 400, MaxConcurrentConnections = 200 });
        Assert.Equal("400", args[args.IndexOf("--max-rate") + 1]);
        Assert.Equal("22,80", args[args.IndexOf("-p") + 1]);

        var weak = new ServiceIdentification { ServiceName = "http-alt", Confidence = 20, Method = "port-hint" };
        var nmapPort = new ImportedPort(8080, TransportProtocol.Tcp, "http", "Apache Tomcat", "9.0.31", "cpe:2.3:a:apache:tomcat:9.0.31:*:*:*:*:*:*:*", null, 100, false);
        var merged = NetworkScanner.WithNmap(weak, nmapPort);
        Assert.Equal(("http", "Apache Tomcat", "9.0.31", "port-hint+nmap"), (merged.ServiceName, merged.Product, merged.Version, merged.Method));
        Assert.True(merged.Confidence <= 80);

        var strong = new ServiceIdentification { ServiceName = "ssh", Product = "OpenSSH", Version = "8.9p1", Confidence = 95, Method = "banner" };
        var kept = NetworkScanner.WithNmap(strong, new ImportedPort(22, TransportProtocol.Tcp, "ssh", "OpenSSH", "9.0", null, null, 100, false));
        Assert.Equal(("OpenSSH", "8.9p1", "banner"), (kept.Product, kept.Version, kept.Method));
        Assert.Equal("ssh OpenSSH 9.0", kept.Extra["nmap.service"]);

        var noVersion = new ServiceIdentification { ServiceName = "http", Product = "nginx", Confidence = 80, Method = "http" };
        Assert.Equal("1.18.0", NetworkScanner.WithNmap(noVersion, new ImportedPort(80, TransportProtocol.Tcp, "http", "nginx", "1.18.0", null, null, 100, false)).Version);
    }
}
