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
/// <param name="WebPaths">Extra safe paths custom signatures need.</param>
/// <param name="ResumeFrom">Addresses of the scope already processed by this scan (a paused scan continues after them).</param>
/// <param name="ExpectedAddresses">Addresses where hosts answered in earlier scans – measured again when silent (unstable hosts).</param>
public sealed record NetworkScanRequest(IReadOnlyList<ScopeEntry> Entries, bool AllowPublicAddresses, string PortSpecification, IReadOnlyList<string>? WebPaths = null,
    int ResumeFrom = 0, IReadOnlySet<IPAddress>? ExpectedAddresses = null);

/// <summary>Where a scan delivers what it finds – the central database (<see cref="ScanEngine"/>) or a remote agent's upload.</summary>
public interface IScanSink
{
    Task EventAsync(ScanEventLevel level, string message);

    /// <summary>The scope was resolved: number of addresses and ports to check.</summary>
    Task ScopeResolvedAsync(int hostsTargeted, int portCount);

    /// <summary>The scanned network: gateway MAC fingerprint and the segments seen on the way.</summary>
    Task NetworkAsync(string? fingerprint, IReadOnlyList<SegmentInfo> segments);

    Task HostAsync(HostScanResult host);

    /// <summary>A subgroup is done: <paramref name="completedAddresses"/> of the scope are processed (the resume point).</summary>
    Task SubgroupCompletedAsync(int completedAddresses) => Task.CompletedTask;
}

/// <param name="Error">Why the scan could not run (invalid scope or ports); null when it completed.</param>
/// <param name="Paused">Stopped at a subgroup boundary because the time window closed; resume later.</param>
public sealed record NetworkScanOutcome(string? Error, bool Paused = false);

/// <summary>
/// The scanning pipeline without any storage: resolve scope → host discovery (ICMP, TCP, ARP, mDNS) → ports → service
/// identification → classification. Used by the central application and by remote agents, so both scan exactly the same
/// way. Cancellation surfaces as <see cref="OperationCanceledException"/>; results delivered before it are kept.
/// </summary>
public sealed class NetworkScanner(OuiDatabase oui, LocalNetworkDiscovery localNetwork, ScanOptions options, ILogger logger)
{
    public const int MinBatchSize = 64;
    /// <summary>Upper bound of a subgroup – keeps resume points and pauses frequent on fast networks.</summary>
    public const int MaxBatchSize = 1024;
    public const double TargetBatchSeconds = 60;

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

        // Subgroups ("podgrupy"): large scopes are scanned piece by piece. The size follows the measured speed (about one
        // minute per subgroup), each finished subgroup is a resume point, and a closing time window pauses the scan between
        // subgroups. Scopes up to one subgroup behave exactly like a single pass.
        var all = scope.Addresses;
        var scopeSet = all.ToHashSet();
        var start = Math.Clamp(request.ResumeFrom, 0, all.Count);
        var batched = all.Count > options.SubgroupThreshold;
        progress.Batched = batched;
        progress.SetHostsTotal(all.Count);
        progress.AddressesDone = start;
        progress.ResumedFrom = start;
        if (start > 0) await sink.EventAsync(ScanEventLevel.Info, $"Wznowienie skanu od adresu {start + 1} z {all.Count} (wcześniejsze podgrupy są już zapisane).");

        var prober = new ServiceProber(options, request.WebPaths);
        var localMacs = localNetwork.GetLocalMacAddresses();
        IReadOnlyDictionary<IPAddress, MdnsHost>? scopeMdns = null;
        string? fingerprint = null;
        var networkReported = false;
        var totalAlive = 0;
        var totalArpOnly = 0;
        var batchSize = batched ? Math.Max(1, options.SubgroupInitialSize) : all.Count;
        var subgroup = 0;
        var watch = System.Diagnostics.Stopwatch.StartNew();
        for (var index = start; index < all.Count;)
        {
            if (progress.PauseRequested)
            {
                await sink.EventAsync(ScanEventLevel.Info, $"Skan wstrzymany po {index} z {all.Count} adresów – {progress.PauseReason ?? "na żądanie"}.");
                return new NetworkScanOutcome(null, Paused: true);
            }

            subgroup++;
            var batch = all.Skip(index).Take(batchSize).ToList();
            progress.BeginSubgroup(subgroup, batch.Count);
            var batchStarted = watch.Elapsed;

            // Phase 1: which hosts exist?
            progress.Phase = ScanPhase.HostDiscovery;
            progress.Activity = batched ? $"Podgrupa {subgroup}: wykrywanie hostów ({batch.Count} adresów)" : "Wykrywanie aktywnych hostów (ICMP, TCP)";
            var alive = new ConcurrentDictionary<IPAddress, LivenessResult>();
            await Parallel.ForEachAsync(batch, new ParallelOptions { MaxDegreeOfParallelism = options.ParallelHostDiscovery, CancellationToken = cancellationToken },
                async (address, ct) =>
                {
                    var result = await NetworkProbe.CheckLivenessAsync(address, options, gate, ct);
                    if (result.IsAlive) alive[address] = result;
                    progress.HostProbed(result.IsAlive);
                });

            // Hosts that answered in earlier scans but not now are measured once more – unstable hosts often answer late.
            if (request.ExpectedAddresses is { Count: > 0 } expected)
            {
                var silent = batch.Where(a => expected.Contains(a) && !alive.ContainsKey(a)).ToList();
                if (silent.Count > 0)
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
                    var recovered = 0;
                    await Parallel.ForEachAsync(silent, new ParallelOptions { MaxDegreeOfParallelism = options.ParallelHostDiscovery, CancellationToken = cancellationToken },
                        async (address, ct) =>
                        {
                            var retry = await NetworkProbe.CheckLivenessAsync(address, options, gate, ct);
                            if (!retry.IsAlive) return;
                            alive[address] = retry;
                            Interlocked.Increment(ref recovered);
                            progress.AddAlive(1);
                        });
                    await sink.EventAsync(ScanEventLevel.Info, $"Ponowny pomiar {silent.Count} hostów, które odpowiadały we wcześniejszych skanach: odpowiedziało {recovered}.");
                }
            }

            // Hosts that answer nothing but still resolved via ARP exist on the local segment (e.g. firewalled devices).
            var arp = ArpTable.Read();
            var batchSet = batch.ToHashSet();
            foreach (var (address, _) in arp)
            {
                if (batchSet.Contains(address) && !alive.ContainsKey(address))
                {
                    alive[address] = new LivenessResult(true, DiscoveryMethod.Arp, null, null, []);
                    totalArpOnly++;
                    progress.AddAlive(1);
                }
            }

            if (!networkReported)
            {
                networkReported = true;
                fingerprint = ScanEngine.NetworkFingerprint(interfaces, all, arp);
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
            }

            if (scopeMdns is null)
            {
                scopeMdns = (await mdnsTask).Where(m => scopeSet.Contains(m.Key)).ToDictionary(m => m.Key, m => m.Value);
                if (scopeMdns.Count > 0)
                {
                    await sink.EventAsync(ScanEventLevel.Info, $"mDNS: {scopeMdns.Count} urządzeń w zakresie ogłasza {scopeMdns.Sum(m => m.Value.Services.Count)} usług.");
                }
            }

            foreach (var (address, host) in scopeMdns.Where(m => batchSet.Contains(m.Key)))
            {
                if (alive.TryGetValue(address, out var known))
                {
                    alive[address] = known with { Methods = known.Methods | DiscoveryMethod.Mdns };
                }
                else
                {
                    alive[address] = new LivenessResult(true, DiscoveryMethod.Mdns, null, null, []);
                    progress.AddAlive(1);
                }
            }

            totalAlive += alive.Count;
            if (!batched)
            {
                await sink.EventAsync(ScanEventLevel.Info,
                    $"Wykrywanie hostów zakończone: {alive.Count} aktywnych z {all.Count} adresów" + (totalArpOnly > 0 ? $" (w tym {totalArpOnly} wyłącznie z tablicy ARP)." : "."));
            }

            // Phase 2: ports and services per live host.
            progress.Phase = ScanPhase.PortScan;
            progress.SetPortsTotal(progress.PortsTotal + alive.Sum(a => ports.Count + (scopeMdns.TryGetValue(a.Key, out var m) ? m.Services.Count(s => s.Port is not null) : 0)));
            await Parallel.ForEachAsync(alive.OrderBy(a => Ipv4Sort(a.Key)), new ParallelOptions { MaxDegreeOfParallelism = options.ParallelHostScans, CancellationToken = cancellationToken },
                async (entry, ct) =>
                {
                    var result = await ScanHostAsync(entry.Key, entry.Value, ports, arp, gateways, localMachine, localMacs, scopeMdns.GetValueOrDefault(entry.Key),
                        scopeNames.GetValueOrDefault(entry.Key), prober, gate, progress, ct);
                    await sink.HostAsync(result);
                    progress.HostCompleted();
                });

            index += batch.Count;
            progress.AddressesDone = index;
            await sink.SubgroupCompletedAsync(index);
            if (batched)
            {
                var seconds = Math.Max(0.5, (watch.Elapsed - batchStarted).TotalSeconds);
                var rate = batch.Count / seconds;
                var remaining = all.Count - index;
                progress.EstimatedEnd = DateTime.UtcNow.AddSeconds(remaining / Math.Max(rate, 0.1));
                await sink.EventAsync(ScanEventLevel.Info, string.Create(System.Globalization.CultureInfo.InvariantCulture,
                    $"Podgrupa {subgroup}{(start > 0 ? " po wznowieniu" : "")}: adresy {batch[0]}–{batch[^1]} ({batch.Count}), aktywne {alive.Count}, {seconds:0} s, tempo {rate:0.0} adr./s; pozostało {remaining} adresów (ok. {remaining / Math.Max(rate, 0.1) / 60:0} min)."));
                // Next subgroup sized for about TargetBatchSeconds at the measured speed.
                batchSize = (int)Math.Clamp(rate * TargetBatchSeconds, MinBatchSize, MaxBatchSize);
            }
        }

        if (batched)
        {
            await sink.EventAsync(ScanEventLevel.Info, start > 0
                ? $"Wykrywanie hostów zakończone: {totalAlive} aktywnych z {all.Count - start} adresów sprawdzonych po wznowieniu ({subgroup} podgrup); wcześniej sprawdzono {start} adresów."
                : $"Wykrywanie hostów zakończone: {totalAlive} aktywnych z {all.Count} adresów w {subgroup} podgrupach" + (totalArpOnly > 0 ? $" (w tym {totalArpOnly} wyłącznie z tablicy ARP)." : "."));
        }

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
