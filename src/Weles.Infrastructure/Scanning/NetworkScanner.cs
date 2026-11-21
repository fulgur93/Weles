using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Discovery;

namespace Weles.Infrastructure.Scanning;

/// <summary>What one scan should do: the approved scope and the ports.</summary>
public sealed record NetworkScanRequest(IReadOnlyList<ScopeEntry> Entries, bool AllowPublicAddresses, string PortSpecification);

/// <summary>Where a scan delivers what it finds – the central database (<see cref="ScanEngine"/>) or a remote agent's upload.</summary>
public interface IScanSink
{
    Task EventAsync(ScanEventLevel level, string message);

    /// <summary>The scope was resolved: number of addresses and ports to check.</summary>
    Task ScopeResolvedAsync(int hostsTargeted, int portCount);

    /// <summary>The scanned network: gateway MAC fingerprint and the segments seen on the way.</summary>
    Task NetworkAsync(string? fingerprint, IReadOnlyList<SegmentInfo> segments);

    Task HostAsync(HostScanResult host);
}

/// <param name="Error">Why the scan could not run (invalid scope or ports); null when it completed.</param>
public sealed record NetworkScanOutcome(string? Error);

/// <summary>
/// The scanning pipeline without any storage: resolve scope → host discovery (ICMP, TCP, ARP, mDNS) → ports → service
/// identification → classification. Used by the central application and by remote agents, so both scan exactly the same
/// way. Cancellation surfaces as <see cref="OperationCanceledException"/>; results delivered before it are kept.
/// </summary>
public sealed class NetworkScanner(OuiDatabase oui, LocalNetworkDiscovery localNetwork, ScanOptions options, ILogger logger)
{
    public async Task<NetworkScanOutcome> RunAsync(NetworkScanRequest request, ScanProgress progress, IScanSink sink, CancellationToken cancellationToken)
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

        var scope = await ScopeResolver.ResolveAsync(request.Entries, request.AllowPublicAddresses, options.MaxHostsPerScan, ResolveDomainAsync, cancellationToken);
        foreach (var warning in scope.Warnings)
        {
            await sink.EventAsync(ScanEventLevel.Warning, warning);
        }

        if (!scope.IsValid) return new NetworkScanOutcome(string.Join(" ", scope.Errors));
        if (!PortSpecification.TryParse(request.PortSpecification, out var ports, out var portError)) return new NetworkScanOutcome(portError!);

        await sink.ScopeResolvedAsync(scope.Addresses.Count, ports.Count);

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

        var fingerprint = ScanEngine.NetworkFingerprint(interfaces, scope.Addresses, arp);
        var scopeGatewayVendor = fingerprint is { } fp ? oui.Lookup(fp.Split(',')[0]) : null;
        await sink.NetworkAsync(fingerprint,
            request.Entries.Where(e => !e.IsExclusion && TargetParser.TryParse(e.Value, out var t, out _) && t.Kind == ScanTargetEntryKind.Cidr)
                .Select(e => new SegmentInfo(e.Value, null, fingerprint, scopeGatewayVendor))
                .Concat(interfaces.Select(i =>
                {
                    var mac = i.Gateway is not null && IPAddress.TryParse(i.Gateway, out var gw) ? arp.GetValueOrDefault(gw)?.ToLowerInvariant() : null;
                    return new SegmentInfo(i.NetworkCidr, i.Gateway, mac, oui.Lookup(mac));
                }))
                .ToList());
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
            await sink.EventAsync(ScanEventLevel.Info, $"mDNS: {scopeMdns.Count} urządzeń w zakresie ogłasza {scopeMdns.Sum(m => m.Value.Services.Count)} usług.");
        }

        progress.AddAlive(arpOnly + mdnsOnly);
        await sink.EventAsync(ScanEventLevel.Info,
            $"Wykrywanie hostów zakończone: {alive.Count} aktywnych z {scope.Addresses.Count} adresów" + (arpOnly > 0 ? $" (w tym {arpOnly} wyłącznie z tablicy ARP)." : "."));

        // Phase 2: ports and services per live host.
        progress.Phase = ScanPhase.PortScan;
        progress.SetPortsTotal(alive.Sum(a => ports.Count + (scopeMdns.TryGetValue(a.Key, out var m) ? m.Services.Count(s => s.Port is not null) : 0)));
        var prober = new ServiceProber(options);
        await Parallel.ForEachAsync(alive.OrderBy(a => Ipv4Sort(a.Key)), new ParallelOptions { MaxDegreeOfParallelism = options.ParallelHostScans, CancellationToken = cancellationToken },
            async (entry, ct) =>
            {
                var result = await ScanHostAsync(entry.Key, entry.Value, ports, arp, gateways, localMachine, localMacs, scopeMdns.GetValueOrDefault(entry.Key),
                    scopeNames.GetValueOrDefault(entry.Key), prober, gate, progress, ct);
                await sink.HostAsync(result);
                progress.HostCompleted();
            });

        progress.Phase = ScanPhase.Finishing;
        return new NetworkScanOutcome(null);
    }

    private async Task<HostScanResult> ScanHostAsync(
        IPAddress address, LivenessResult liveness, IReadOnlyList<int> ports, IReadOnlyDictionary<IPAddress, string> arp,
        IReadOnlySet<IPAddress> gateways, IReadOnlyDictionary<IPAddress, string?> localMachine, IReadOnlySet<string> localMacs, MdnsHost? mdns, string? scopeName,
        ServiceProber prober, ConnectionGate gate, ScanProgress progress, CancellationToken ct)
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
                    probe = probe with { Identification = ScanEngine.WithMdnsHint(probe.Identification, announced) };
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

    private static long Ipv4Sort(IPAddress a) => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? Ipv4.ToUInt(a) : long.MaxValue;
}
