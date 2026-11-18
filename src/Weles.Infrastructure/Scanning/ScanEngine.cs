using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Discovery;

namespace Weles.Infrastructure.Scanning;

/// <summary>
/// Runs one approved scan: resolve scope → host discovery → port scan → service identification → persist.
/// </summary>
public sealed class ScanEngine(
    IDbContextFactory<WelesDbContext> contextFactory,
    ScanResultWriter writer,
    OuiDatabase oui,
    LocalNetworkDiscovery localNetwork,
    IOptions<ScanOptions> optionsAccessor,
    TimeProvider timeProvider,
    ILogger<ScanEngine> logger)
{
    public async Task RunAsync(int scanId, ScanProgress progress, CancellationToken cancellationToken)
    {
        var options = optionsAccessor.Value;
        await using var db = await contextFactory.CreateDbContextAsync(CancellationToken.None);
        var scan = await db.Scans.Include(s => s.ScanTarget!).ThenInclude(t => t.Entries).SingleAsync(s => s.Id == scanId, CancellationToken.None);
        var target = scan.ScanTarget!;

        if (scan.Status != ScanStatus.Pending)
        {
            logger.LogWarning("Scan {ScanId} is in state {Status} and will not be started", scanId, scan.Status);
            return;
        }

        if (!target.IsApproved)
        {
            await FailAsync(db, scan, "Zakres skanowania nie jest zatwierdzony – skan odrzucony.");
            return;
        }

        if (cancellationToken.IsCancellationRequested)
        {
            await FinishAsync(db, scan, ScanStatus.Cancelled, "Skan zatrzymany przed rozpoczęciem.");
            return;
        }

        scan.Status = ScanStatus.Running;
        scan.StartedAt = Now;
        scan.SettingsJson = JsonSerializer.Serialize(new
        {
            options.MaxConcurrentConnections, options.ConnectionsPerSecond, options.ConnectTimeoutMs,
            options.ParallelHostDiscovery, options.ParallelHostScans, options.UseIcmp
        });
        scan.ScopeSnapshot = JsonSerializer.Serialize(target.Entries.Select(e => new { e.Value, e.IsExclusion }));
        await db.SaveChangesAsync(CancellationToken.None);

        logger.LogInformation("Scan {ScanId} started for scope {Target} (ports: {Ports})", scanId, target.Name, scan.PortSpecification);
        await writer.AddEventAsync(scanId, ScanEventLevel.Info, $"Rozpoczęto skan zakresu „{target.Name}” (porty: {scan.PortSpecification}).");

        try
        {
            progress.Phase = ScanPhase.ResolvingScope;
            progress.Activity = "Rozwiązywanie zakresu";
            var scope = await ScopeResolver.ResolveAsync(
                target.Entries.Select(e => new ScopeEntry(e.Value, e.IsExclusion)),
                target.AllowPublicAddresses, options.MaxHostsPerScan, ResolveDomainAsync, cancellationToken);

            foreach (var warning in scope.Warnings)
            {
                await writer.AddEventAsync(scanId, ScanEventLevel.Warning, warning);
            }

            if (!scope.IsValid)
            {
                await FailAsync(db, scan, string.Join(" ", scope.Errors));
                return;
            }

            if (!PortSpecification.TryParse(scan.PortSpecification, out var ports, out var portError))
            {
                await FailAsync(db, scan, portError!);
                return;
            }

            scan.HostsTargeted = scope.Addresses.Count;
            scan.PortCount = ports.Count;
            await db.SaveChangesAsync(CancellationToken.None);

            var interfaces = localNetwork.GetInterfaces();
            await writer.EnsureSegmentsAsync(
                target.Entries.Where(e => !e.IsExclusion && e.Kind == ScanTargetEntryKind.Cidr).Select(e => (e.Value, (string?)null))
                    .Concat(interfaces.Select(i => (i.NetworkCidr, i.Gateway))));
            var gateways = localNetwork.GetGateways();

            await using var gate = new ConnectionGate(options.MaxConcurrentConnections, options.ConnectionsPerSecond);

            // Phase 1: which hosts exist?
            progress.Phase = ScanPhase.HostDiscovery;
            progress.SetHostsTotal(scope.Addresses.Count);
            progress.Activity = "Wykrywanie aktywnych hostów (ICMP, TCP)";
            var alive = new ConcurrentDictionary<IPAddress, LivenessResult>();
            await Parallel.ForEachAsync(scope.Addresses, new ParallelOptions { MaxDegreeOfParallelism = options.ParallelHostDiscovery, CancellationToken = cancellationToken },
                async (address, ct) =>
                {
                    var result = await NetworkProbe.CheckLivenessAsync(address, options, gate, ct);
                    if (result.IsAlive) alive[address] = result;
                    progress.HostProbed(result.IsAlive);
                });

            // Hosts that answer nothing but still resolved via ARP exist on the local segment (e.g. firewalled devices).
            var arp = ArpTable.Read();
            var scopeSet = scope.Addresses.ToHashSet();
            var arpOnly = 0;
            foreach (var (address, _) in arp)
            {
                if (scopeSet.Contains(address) && !alive.ContainsKey(address))
                {
                    alive[address] = new LivenessResult(true, DiscoveryMethod.Arp, null, null, []);
                    arpOnly++;
                }
            }

            progress.AddAlive(arpOnly);
            await writer.AddEventAsync(scanId, ScanEventLevel.Info,
                $"Wykrywanie hostów zakończone: {alive.Count} aktywnych z {scope.Addresses.Count} adresów" + (arpOnly > 0 ? $" (w tym {arpOnly} wyłącznie z tablicy ARP)." : "."));

            // Phase 2: ports and services per live host.
            progress.Phase = ScanPhase.PortScan;
            progress.SetPortsTotal(alive.Count * ports.Count);
            var prober = new ServiceProber(options);
            await Parallel.ForEachAsync(alive.OrderBy(a => Ipv4Sort(a.Key)), new ParallelOptions { MaxDegreeOfParallelism = options.ParallelHostScans, CancellationToken = cancellationToken },
                async (entry, ct) =>
                {
                    var result = await ScanHostAsync(entry.Key, entry.Value, ports, arp, gateways, prober, gate, options, progress, ct);
                    await writer.SaveHostAsync(scanId, result);
                    progress.HostCompleted();
                });

            progress.Phase = ScanPhase.Finishing;
            scan.HostsProbed = progress.HostsProbed;
            await FinishAsync(db, scan, ScanStatus.Completed,
                $"Skan zakończony: {progress.HostsAlive} hostów, {progress.OpenPorts} otwartych portów, {progress.ServicesIdentified} rozpoznanych usług.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            scan.HostsProbed = progress.HostsProbed;
            await FinishAsync(db, scan, ScanStatus.Cancelled, $"Skan zatrzymany. Zachowano wyniki dla {progress.HostsCompleted} hostów.");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Scan {ScanId} failed", scanId);
            await FailAsync(db, scan, $"Błąd skanowania: {ex.Message}");
        }
    }

    private async Task<HostScanResult> ScanHostAsync(
        IPAddress address, LivenessResult liveness, IReadOnlyList<int> ports, IReadOnlyDictionary<IPAddress, string> arp,
        IReadOnlySet<IPAddress> gateways, ServiceProber prober, ConnectionGate gate, ScanOptions options, ScanProgress progress, CancellationToken ct)
    {
        progress.Activity = $"Skanowanie portów {address}";
        var open = new ConcurrentDictionary<int, string>();
        foreach (var known in liveness.OpenPorts.Where(ports.Contains)) open[known] = "syn-ack";

        await Parallel.ForEachAsync(ports, new ParallelOptions { MaxDegreeOfParallelism = 64, CancellationToken = ct }, async (port, token) =>
        {
            if (open.ContainsKey(port))
            {
                progress.PortChecked(true);
                return;
            }

            using var _ = await gate.AcquireAsync(token);
            var result = await NetworkProbe.TcpConnectAsync(address, port, options.ConnectTimeoutMs, token);
            if (result.State == PortState.Open) open[port] = result.Reason;
            progress.PortChecked(result.State == PortState.Open);
        });

        var hostname = await NetworkProbe.ReverseDnsAsync(address, options.DnsTimeoutMs, ct);

        progress.Activity = $"Rozpoznawanie usług {address}";
        var services = new ConcurrentBag<PortScanResult>();
        await Parallel.ForEachAsync(open.OrderBy(p => p.Key), new ParallelOptions { MaxDegreeOfParallelism = options.ParallelServiceProbesPerHost, CancellationToken = ct },
            async (port, token) =>
            {
                ServiceProbeResult probe;
                using (await gate.AcquireAsync(token))
                {
                    probe = await prober.ProbeAsync(address, port.Key, hostname, token);
                }

                if (probe.Identification.Method != "port-hint") progress.ServiceIdentified();
                services.Add(new PortScanResult(port.Key, port.Value, probe));
            });

        var mac = arp.GetValueOrDefault(address);
        var vendor = oui.Lookup(mac);
        var isGateway = gateways.Contains(address);
        var portList = services.OrderBy(s => s.Port).ToList();
        var classification = AssetClassifier.Classify(new HostEvidence(
            portList.Select(p => p.Port).ToList(),
            portList.Select(p => p.Service!.Identification).ToList(),
            vendor, liveness.Ttl, isGateway, hostname));

        var methods = liveness.Methods | (mac is not null ? DiscoveryMethod.Arp : DiscoveryMethod.None) | (hostname is not null ? DiscoveryMethod.Dns : DiscoveryMethod.None);
        return new HostScanResult(address, methods, liveness.RoundTripMs, liveness.Ttl, hostname, mac, vendor, isGateway, classification, portList);
    }

    private static async Task<IReadOnlyList<IPAddress>> ResolveDomainAsync(string domain, CancellationToken ct) =>
        await Dns.GetHostAddressesAsync(domain, ct);

    private async Task FinishAsync(WelesDbContext db, Scan scan, ScanStatus status, string message)
    {
        await db.Entry(scan).ReloadAsync(CancellationToken.None); // counters were updated by the writer
        scan.Status = status;
        scan.CompletedAt = Now;
        await db.SaveChangesAsync(CancellationToken.None);
        await writer.AddEventAsync(scan.Id, status == ScanStatus.Completed ? ScanEventLevel.Info : ScanEventLevel.Warning, message);
        logger.LogInformation("Scan {ScanId} finished with status {Status}: {HostsAlive} hosts, {OpenPorts} open ports", scan.Id, status, scan.HostsAlive, scan.OpenPorts);
    }

    private async Task FailAsync(WelesDbContext db, Scan scan, string message)
    {
        await db.Entry(scan).ReloadAsync(CancellationToken.None);
        scan.Status = ScanStatus.Failed;
        scan.ErrorMessage = message.Length > 2000 ? message[..2000] : message;
        scan.CompletedAt = Now;
        await db.SaveChangesAsync(CancellationToken.None);
        await writer.AddEventAsync(scan.Id, ScanEventLevel.Error, message);
        logger.LogWarning("Scan {ScanId} failed: {Message}", scan.Id, message);
    }

    private static long Ipv4Sort(IPAddress a) => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? Ipv4.ToUInt(a) : long.MaxValue;

    private DateTime Now => timeProvider.GetUtcNow().UtcDateTime;
}
