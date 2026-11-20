using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using Weles.Core.Rules;

namespace Weles.Infrastructure.External;

/// <param name="Rcode">DNS response code; -1 when no server answered.</param>
public sealed record DnsAnswer(int Rcode, IReadOnlyList<DnsRecord> Records)
{
    public bool Answered => Rcode >= 0;
    public bool NameDoesNotExist => Rcode == DnsMessage.RcodeNameError;
}

/// <summary>
/// Plain DNS queries (UDP, TCP when the answer is truncated) to the resolvers of the operating system – the same queries
/// any mail server or browser makes. No zone transfers and no name guessing: only names from authorised sources are asked.
/// </summary>
public sealed class DnsLookup(IOptions<ExternalOptions> options)
{
    public IReadOnlyList<IPEndPoint> Servers { get; } = ResolveServers(options.Value.DnsServers);

    public async Task<DnsAnswer> QueryAsync(string name, ushort type, CancellationToken ct)
    {
        foreach (var server in Servers)
        {
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
                var query = DnsMessage.BuildQuery(id, [(name, type)], recursionDesired: true);
                var response = await UdpAsync(server, query, ct);
                if (response is null) continue;
                if (!DnsMessage.TryParse(response, out var rid, out var rcode, out var truncated, out var records) || rid != id) continue;
                if (truncated)
                {
                    var tcp = await TcpAsync(server, query, ct);
                    if (tcp is not null && DnsMessage.TryParse(tcp, out rid, out rcode, out _, out var full) && rid == id) records = full;
                }

                if (rcode == DnsMessage.RcodeServerFailure) break; // try the next resolver
                return new DnsAnswer(rcode, records);
            }
        }

        return new DnsAnswer(-1, []);
    }

    private async Task<byte[]?> UdpAsync(IPEndPoint server, byte[] query, CancellationToken ct)
    {
        using var udp = new UdpClient(server.AddressFamily);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(options.Value.DnsTimeoutMs);
        try
        {
            await udp.SendAsync(query, server, timeout.Token);
            while (true)
            {
                var result = await udp.ReceiveAsync(timeout.Token);
                if (result.RemoteEndPoint.Equals(server)) return result.Buffer;
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
        catch (SocketException)
        {
            return null;
        }
    }

    private async Task<byte[]?> TcpAsync(IPEndPoint server, byte[] query, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(options.Value.DnsTimeoutMs * 2);
        try
        {
            using var tcp = new TcpClient(server.AddressFamily);
            await tcp.ConnectAsync(server, timeout.Token);
            var stream = tcp.GetStream();
            var framed = new byte[query.Length + 2];
            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
            query.CopyTo(framed, 2);
            await stream.WriteAsync(framed, timeout.Token);
            var lengthBytes = new byte[2];
            await stream.ReadExactlyAsync(lengthBytes, timeout.Token);
            var response = new byte[BinaryPrimitives.ReadUInt16BigEndian(lengthBytes)];
            await stream.ReadExactlyAsync(response, timeout.Token);
            return response;
        }
        catch (Exception ex) when (ex is SocketException or IOException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            return null;
        }
    }

    private static IReadOnlyList<IPEndPoint> ResolveServers(string[] configured)
    {
        var servers = configured.Select(Parse).OfType<IPEndPoint>().ToList();
        if (servers.Count > 0) return servers;
        try
        {
            servers = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .SelectMany(n => n.GetIPProperties().DnsAddresses)
                .Where(a => !a.IsIPv6LinkLocal)
                .Distinct()
                .OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
                .Select(a => new IPEndPoint(a, 53))
                .ToList();
        }
        catch (NetworkInformationException)
        {
            servers = [];
        }

        if (servers.Count == 0 && File.Exists("/etc/resolv.conf"))
        {
            servers = File.ReadLines("/etc/resolv.conf")
                .Select(l => l.Trim().Split(' ', '\t', StringSplitOptions.RemoveEmptyEntries))
                .Where(p => p.Length >= 2 && p[0] == "nameserver")
                .Select(p => Parse(p[1])).OfType<IPEndPoint>().ToList();
        }

        return servers;
    }

    private static IPEndPoint? Parse(string value) =>
        IPEndPoint.TryParse(value.Trim(), out var ep) ? (ep.Port == 0 ? new IPEndPoint(ep.Address, 53) : ep) : null;
}
