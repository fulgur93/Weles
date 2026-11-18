using System.Net;
using System.Net.Sockets;
using Weles.Core.Rules;

namespace Weles.Infrastructure.Scanning;

public sealed record MdnsService(string Type, string Instance, int? Port, IReadOnlyList<string> Txt);

public sealed record MdnsHost(IPAddress Address, string? Hostname, IReadOnlyList<MdnsService> Services);

/// <summary>
/// DNS-SD over multicast DNS (RFC 6762/6763), link-local only. WELES sends "legacy unicast" queries
/// (from an ephemeral port, not 5353), so responders answer directly to WELES and nothing needs to bind port 5353.
/// The queries are read-only questions; devices only answer about services they already advertise.
/// </summary>
public static class MdnsDiscovery
{
    public static readonly IPEndPoint MulticastEndpoint = new(IPAddress.Parse("224.0.0.251"), 5353);

    public static async Task<IReadOnlyDictionary<IPAddress, MdnsHost>> DiscoverAsync(
        IEnumerable<IPAddress> localAddresses, int listenMs, CancellationToken ct, IPEndPoint? target = null)
    {
        var endpoint = target ?? MulticastEndpoint;
        var records = new List<(IPAddress From, DnsRecord Record)>();

        var sockets = localAddresses.Distinct().Select(local =>
        {
            try
            {
                var udp = new UdpClient(new IPEndPoint(local, 0));
                if (target is null)
                {
                    udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);
                    udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, local.GetAddressBytes());
                    udp.MulticastLoopback = false;
                }

                return udp;
            }
            catch (SocketException)
            {
                return null;
            }
        }).OfType<UdpClient>().ToList();

        try
        {
            // Round 1: service enumeration + always-interesting types. Round 2: every type somebody announced.
            var round1 = MdnsServiceCatalog.InterestingTypes.Select(t => t + ".local").Prepend("_services._dns-sd._udp.local").ToList();
            await QueryRoundAsync(sockets, endpoint, round1, listenMs / 2, records, ct);

            var announcedTypes = records.Where(r => r.Record.Type == DnsMessage.TypePtr && r.Record.Name.StartsWith("_services._dns-sd", StringComparison.OrdinalIgnoreCase))
                .Select(r => r.Record.Target!).Where(t => !round1.Contains(t, StringComparer.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase).Take(40).ToList();
            if (announcedTypes.Count > 0)
            {
                await QueryRoundAsync(sockets, endpoint, announcedTypes, listenMs / 2, records, ct);
            }
        }
        finally
        {
            foreach (var s in sockets) s.Dispose();
        }

        return Aggregate(records);
    }

    private static async Task QueryRoundAsync(List<UdpClient> sockets, IPEndPoint endpoint, List<string> names, int listenMs, List<(IPAddress, DnsRecord)> sink, CancellationToken ct)
    {
        // Keep packets well under a typical MTU.
        foreach (var chunk in names.Chunk(12))
        {
            var query = DnsMessage.BuildQuery((ushort)Random.Shared.Next(1, ushort.MaxValue), chunk.Select(n => (n, DnsMessage.TypePtr)));
            foreach (var socket in sockets)
            {
                try { await socket.SendAsync(query, endpoint, ct); }
                catch (SocketException) { /* interface without multicast route */ }
            }
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(listenMs);
        await Task.WhenAll(sockets.Select(async socket =>
        {
            while (!deadline.IsCancellationRequested)
            {
                UdpReceiveResult packet;
                try { packet = await socket.ReceiveAsync(deadline.Token); }
                catch (OperationCanceledException) { break; }
                catch (SocketException) { continue; }

                if (packet.Buffer.Length > 9000 || !DnsMessage.TryParse(packet.Buffer, out _, out var parsed)) continue;
                lock (sink)
                {
                    foreach (var r in parsed) sink.Add((packet.RemoteEndPoint.Address, r));
                }
            }
        }));
        ct.ThrowIfCancellationRequested();
    }

    /// <summary>Joins PTR → SRV/TXT → A records and groups services by the responding host.</summary>
    internal static IReadOnlyDictionary<IPAddress, MdnsHost> Aggregate(IReadOnlyList<(IPAddress From, DnsRecord Record)> records)
    {
        var srv = records.Where(r => r.Record.Type == DnsMessage.TypeSrv).GroupBy(r => r.Record.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Record, StringComparer.OrdinalIgnoreCase);
        var txt = records.Where(r => r.Record.Type == DnsMessage.TypeTxt).GroupBy(r => r.Record.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Record.Texts ?? [], StringComparer.OrdinalIgnoreCase);
        var addresses = records.Where(r => r.Record.Type == DnsMessage.TypeA && r.Record.Address is not null)
            .GroupBy(r => r.Record.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Record.Address!, StringComparer.OrdinalIgnoreCase);

        var hosts = new Dictionary<IPAddress, (string? Hostname, List<MdnsService> Services)>();
        foreach (var (from, ptr) in records.Where(r => r.Record.Type == DnsMessage.TypePtr && !r.Record.Name.StartsWith("_services._dns-sd", StringComparison.OrdinalIgnoreCase)))
        {
            var instance = ptr.Target!;
            srv.TryGetValue(instance, out var service);
            var host = service?.Target is { } t && addresses.TryGetValue(t, out var a) ? a : from;
            if (host.IsIPv4MappedToIPv6) host = host.MapToIPv4();

            if (!hosts.TryGetValue(host, out var entry)) hosts[host] = entry = (service?.Target, []);
            if (entry.Hostname is null && service?.Target is not null) hosts[host] = entry = (service.Target, entry.Services);

            var type = MdnsServiceCatalog.Normalize(ptr.Name);
            var label = instance.EndsWith("." + ptr.Name, StringComparison.OrdinalIgnoreCase) ? instance[..^(ptr.Name.Length + 1)] : instance;
            if (entry.Services.Any(s => s.Type == type && s.Instance == label)) continue;
            entry.Services.Add(new MdnsService(type, BannerParser.Sanitize(label), service?.Port, txt.GetValueOrDefault(instance) ?? []));
        }

        return hosts.ToDictionary(h => h.Key, h => new MdnsHost(h.Key, h.Value.Hostname?.TrimEnd('.').ToLowerInvariant(), h.Value.Services));
    }
}
