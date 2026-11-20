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
            // Addresses that came from a domain entry keep that name: it is sent as TLS SNI / HTTP Host (a public server
            // often hosts several sites on one address) and names the device.
            var scopeNames = new ConcurrentDictionary<IPAddress, string>();
            async Task<IReadOnlyList<IPAddress>> ResolveDomainAsync(string domain, CancellationToken token)
            {
                var resolved = await Dns.GetHostAddressesAsync(domain, token);
                foreach (var a in resolved) scopeNames.TryAdd(a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a, domain);
                return resolved;
            }

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
            var gateways = localNetwork.GetGateways();
            // The machine running WELES is not in its own ARP table – take its MAC from the local interface.
            var localMachine = interfaces.Where(i => IPAddress.TryParse(i.Address, out _))
                .GroupBy(i => IPAddress.Parse(i.Address)).ToDictionary(g => g.Key, g => g.First().MacAddress);

            await using var gate = new ConnectionGate(options.MaxConcurrentConnections, options.ConnectionsPerSecond);

            // mDNS runs in parallel with host discovery; it only reaches the local link.
            var localAddresses = interfaces.Select(i => IPAddress.Parse(i.Address)).Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToList();
            var mdnsTask = options.UseMdns && localAddresses.Count > 0
                ? DiscoverMdnsSafelyAsync(localAddresses, options.MdnsListenMs, cancellationToken)
                : Task.FromResult<IReadOnlyDictionary<IPAddress, MdnsHost>>(new Dictionary<IPAddress, MdnsHost>());

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

            scan.NetworkFingerprint = NetworkFingerprint(interfaces, scope.Addresses, arp);
            await db.SaveChangesAsync(CancellationToken.None);
            var scopeGatewayVendor = scan.NetworkFingerprint is { } fp ? oui.Lookup(fp.Split(',')[0]) : null;
            await writer.EnsureSegmentsAsync(
                target.Entries.Where(e => !e.IsExclusion && e.Kind == ScanTargetEntryKind.Cidr)
                    .Select(e => new SegmentInfo(e.Value, null, scan.NetworkFingerprint, scopeGatewayVendor))
                    .Concat(interfaces.Select(i =>
                    {
                        var mac = i.Gateway is not null && IPAddress.TryParse(i.Gateway, out var gw) ? arp.GetValueOrDefault(gw)?.ToLowerInvariant() : null;
                        return new SegmentInfo(i.NetworkCidr, i.Gateway, mac, oui.Lookup(mac));
                    })));
            var localMacs = localNetwork.GetLocalMacAddresses();

            var scopeMdns = (await mdnsTask).Where(m => scopeSet.Contains(m.Key)).ToDictionary(m => m.Key, m => m.Value);
            var mdnsOnly = 0;
            foreach (var (address, host) in scopeMdns)
            {
                if (alive.TryGetValue(address, out var known))
                {
                    alive[address] = known with { Methods = known.Methods | DiscoveryMethod.Mdns };
                }
                else
                {
                    alive[address] = new LivenessResult(true, DiscoveryMethod.Mdns, null, null, []);
                    mdnsOnly++;
                }
            }

            if (scopeMdns.Count > 0)
            {
                await writer.AddEventAsync(scanId, ScanEventLevel.Info,
                    $"mDNS: {scopeMdns.Count} urządzeń w zakresie ogłasza {scopeMdns.Sum(m => m.Value.Services.Count)} usług.");
            }

            progress.AddAlive(arpOnly + mdnsOnly);
            await writer.AddEventAsync(scanId, ScanEventLevel.Info,
                $"Wykrywanie hostów zakończone: {alive.Count} aktywnych z {scope.Addresses.Count} adresów" + (arpOnly > 0 ? $" (w tym {arpOnly} wyłącznie z tablicy ARP)." : "."));

            // Phase 2: ports and services per live host.
            progress.Phase = ScanPhase.PortScan;
            progress.SetPortsTotal(alive.Sum(a => ports.Count + (scopeMdns.TryGetValue(a.Key, out var m) ? m.Services.Count(s => s.Port is not null) : 0)));
            var prober = new ServiceProber(options);
            await Parallel.ForEachAsync(alive.OrderBy(a => Ipv4Sort(a.Key)), new ParallelOptions { MaxDegreeOfParallelism = options.ParallelHostScans, CancellationToken = cancellationToken },
                async (entry, ct) =>
                {
                    var result = await ScanHostAsync(entry.Key, entry.Value, ports, arp, gateways, localMachine, localMacs, scopeMdns.GetValueOrDefault(entry.Key), scopeNames.GetValueOrDefault(entry.Key), prober, gate, options, progress, ct);
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
        IReadOnlySet<IPAddress> gateways, IReadOnlyDictionary<IPAddress, string?> localMachine, IReadOnlySet<string> localMacs, MdnsHost? mdns, string? scopeName, ServiceProber prober, ConnectionGate gate, ScanOptions options, ScanProgress progress, CancellationToken ct)
    {
        progress.Activity = $"Skanowanie portów {address}";
        // Per-host limits on top of the global gate, so no single device sees a connection flood.
        await using var hostGate = new ConnectionGate(options.MaxConcurrentConnectionsPerHost, options.ConnectionsPerSecondPerHost);
        var open = new ConcurrentDictionary<int, string>();
        foreach (var known in liveness.OpenPorts.Where(ports.Contains)) open[known] = "syn-ack";

        // Ports advertised over mDNS (e.g. Android wireless debugging on a random port) are always checked.
        var announcedPorts = mdns?.Services.Where(s => s.Port is > 0).Select(s => s.Port!.Value) ?? [];
        var portsToCheck = ports.Concat(announcedPorts).Distinct().ToList();

        await Parallel.ForEachAsync(portsToCheck, new ParallelOptions { MaxDegreeOfParallelism = 64, CancellationToken = ct }, async (port, token) =>
        {
            if (open.ContainsKey(port))
            {
                progress.PortChecked(true);
                return;
            }

            using var host = await hostGate.AcquireAsync(token);
            using var _ = await gate.AcquireAsync(token);
            var result = await NetworkProbe.TcpConnectAsync(address, port, options.ConnectTimeoutMs, token);
            if (result.State == PortState.Open) open[port] = result.Reason;
            progress.PortChecked(result.State == PortState.Open);
        });

        var hostname = scopeName ?? await NetworkProbe.ReverseDnsAsync(address, options.DnsTimeoutMs, ct) ?? mdns?.Hostname;

        progress.Activity = $"Rozpoznawanie usług {address}";
        var services = new ConcurrentBag<PortScanResult>();
        await Parallel.ForEachAsync(open.OrderBy(p => p.Key), new ParallelOptions { MaxDegreeOfParallelism = options.ParallelServiceProbesPerHost, CancellationToken = ct },
            async (port, token) =>
            {
                ServiceProbeResult probe;
                using (await hostGate.AcquireAsync(token))
                using (await gate.AcquireAsync(token))
                {
                    probe = await prober.ProbeAsync(address, port.Key, hostname, token);
                }

                if (mdns?.Services.FirstOrDefault(s => s.Port == port.Key) is { } announced)
                {
                    probe = probe with { Identification = WithMdnsHint(probe.Identification, announced) };
                }

                if (probe.Identification.Method != "port-hint") progress.ServiceIdentified();
                services.Add(new PortScanResult(port.Key, port.Value, probe));
            });

        var isLocal = localMachine.TryGetValue(address, out var localMac) || IPAddress.IsLoopback(address);
        var mac = arp.GetValueOrDefault(address) ?? localMac;
        var vendor = oui.Lookup(mac);
        var isGateway = gateways.Contains(address);
        var portList = services.OrderBy(s => s.Port).ToList();
        var classification = AssetClassifier.Classify(new HostEvidence(
            portList.Select(p => p.Port).ToList(),
            portList.Select(p => p.Service!.Identification).ToList(),
            vendor, liveness.Ttl, isGateway, hostname,
            IsLocalMachine: isLocal,
            HasRandomizedMac: OuiDatabase.TryParseMac(mac, out var macBytes) && OuiDatabase.IsLocallyAdministered(macBytes),
            MdnsServiceTypes: mdns?.Services.Select(s => s.Type).ToList()));

        var methods = liveness.Methods | (mac is not null ? DiscoveryMethod.Arp : DiscoveryMethod.None) | (hostname is not null ? DiscoveryMethod.Dns : DiscoveryMethod.None);
        return new HostScanResult(address, methods, liveness.RoundTripMs, liveness.Ttl, hostname, mac, vendor, isGateway, classification, portList, mdns?.Services,
            isLocal && !IPAddress.IsLoopback(address) ? localMacs : null);
    }

    /// <summary>Gateway MAC of every local interface whose network contains part of the scope.</summary>
    internal static string? NetworkFingerprint(IReadOnlyList<LocalInterfaceInfo> interfaces, IReadOnlyList<IPAddress> scope, IReadOnlyDictionary<IPAddress, string> arp)
    {
        var scopeValues = scope.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Select(Ipv4.ToUInt).ToList();
        var macs = interfaces
            .Where(i => i.Gateway is not null && IPAddress.TryParse(i.Address, out _))
            .Where(i =>
            {
                var range = Ipv4.CidrRange(Ipv4.ToUInt(IPAddress.Parse(i.Address)), i.PrefixLength, hostsOnly: false);
                return scopeValues.Any(range.Contains);
            })
            .Select(i => IPAddress.TryParse(i.Gateway, out var gw) ? arp.GetValueOrDefault(gw) : null);
        return Core.Networking.NetworkIdentity.Fingerprint(macs);
    }

    /// <summary>The device's own announcement names a service that did not identify itself to the probes.</summary>
    internal static Core.Models.ServiceIdentification WithMdnsHint(Core.Models.ServiceIdentification id, MdnsService announced)
    {
        var entry = MdnsServiceCatalog.Find(announced.Type);
        id.Extra["mdns.service"] = entry?.Label ?? announced.Type;
        id.Extra["mdns.instance"] = announced.Instance;
        if (announced.Txt.Count > 0) id.Extra["mdns.txt"] = string.Join("; ", announced.Txt.Take(8)) is var t && t.Length > 300 ? t[..300] : t;
        if (entry?.IsRisky == true) id.Extra["mdns.risky"] = "true";

        var weak = id.Method is "port-hint" or "banner-unrecognized" or "tls-handshake";
        return !weak || entry is null ? id : id with
        {
            ServiceName = id.IsTls && !entry.ServiceName.Contains("tls") ? $"ssl/{entry.ServiceName}" : entry.ServiceName,
            OsHint = id.OsHint ?? entry.Os,
            Confidence = Math.Max(id.Confidence, 70),
            Method = id.Method + "+mdns"
        };
    }

    private async Task<IReadOnlyDictionary<IPAddress, MdnsHost>> DiscoverMdnsSafelyAsync(IReadOnlyList<IPAddress> local, int listenMs, CancellationToken ct)
    {
        try
        {
            return await MdnsDiscovery.DiscoverAsync(local, listenMs, ct);
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or IOException)
        {
            logger.LogWarning(ex, "mDNS discovery failed – continuing without it");
            return new Dictionary<IPAddress, MdnsHost>();
        }
    }

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
