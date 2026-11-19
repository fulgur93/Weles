using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Weles.Core.Enums;

namespace Weles.Infrastructure.Scanning;

public sealed record ConnectResult(PortState State, string Reason);

public sealed record LivenessResult(bool IsAlive, DiscoveryMethod Methods, double? RoundTripMs, int? Ttl, IReadOnlyList<int> OpenPorts);

/// <summary>Unprivileged network probes: TCP connect, ICMP echo via the OS, reverse DNS.</summary>
public static class NetworkProbe
{
    public static async Task<ConnectResult> TcpConnectAsync(IPAddress address, int port, int timeoutMs, CancellationToken cancellationToken)
    {
        using var socket = CreateSocket(address);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(timeoutMs);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), timeout.Token);
            CloseGracefully(socket);
            return new ConnectResult(PortState.Open, "syn-ack");
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return new ConnectResult(PortState.Closed, "reset");
        }
        catch (SocketException ex)
        {
            return new ConnectResult(PortState.Filtered, ex.SocketErrorCode switch
            {
                SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.HostDown => "unreachable",
                SocketError.TimedOut => "timeout",
                _ => ex.SocketErrorCode.ToString().ToLowerInvariant()
            });
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new ConnectResult(PortState.Filtered, "timeout");
        }
    }

    /// <summary>Opens a connected stream or returns null. The caller owns the returned client.</summary>
    public static async Task<TcpClient?> OpenAsync(IPAddress address, int port, int timeoutMs, CancellationToken cancellationToken)
    {
        var client = new GracefulTcpClient(address.AddressFamily) { NoDelay = true };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(timeoutMs);
        try
        {
            await client.ConnectAsync(address, port, timeout.Token);
            return client;
        }
        catch (Exception ex) when (ex is SocketException || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            client.Dispose();
            return null;
        }
    }

    public static async Task<(bool Success, double? RoundTripMs, int? Ttl)> PingAsync(IPAddress address, int timeoutMs)
    {
        try
        {
            // Default payload on purpose: without CAP_NET_RAW, .NET on Linux falls back to the system "ping"
            // utility, which rejects custom payloads and options (PlatformNotSupportedException).
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(address, timeoutMs);
            return reply.Status == IPStatus.Success ? (true, reply.RoundtripTime, reply.Options?.Ttl) : (false, null, null);
        }
        catch (Exception ex) when (ex is PingException or PlatformNotSupportedException or InvalidOperationException or SocketException)
        {
            return (false, null, null);
        }
    }

    public static async Task<string?> ReverseDnsAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(timeoutMs);
        try
        {
            var entry = await Dns.GetHostEntryAsync(address.ToString(), timeout.Token);
            var name = entry.HostName?.TrimEnd('.');
            // systemd-resolved synthesizes "_gateway" (and "_outbound") – they are not real host names.
            return string.IsNullOrWhiteSpace(name) || name.StartsWith('_') || IPAddress.TryParse(name, out _) ? null : name.ToLowerInvariant();
        }
        catch (Exception ex) when (ex is SocketException || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            return null;
        }
    }

    public static async Task<LivenessResult> CheckLivenessAsync(IPAddress address, ScanOptions options, ConnectionGate gate, CancellationToken cancellationToken)
    {
        var pingTask = options.UseIcmp ? PingAsync(address, options.PingTimeoutMs) : Task.FromResult<(bool, double?, int?)>((false, null, null));

        var tcpTasks = options.LivenessPorts.Distinct().Select(async port =>
        {
            using var _ = await gate.AcquireAsync(cancellationToken);
            return (port, result: await TcpConnectAsync(address, port, options.ConnectTimeoutMs, cancellationToken));
        }).ToList();

        var tcp = await Task.WhenAll(tcpTasks);
        var (pingOk, rtt, ttl) = await pingTask;

        var methods = DiscoveryMethod.None;
        if (pingOk) methods |= DiscoveryMethod.Icmp;
        // A RST proves the host exists just as well as a SYN-ACK.
        if (tcp.Any(t => t.result.State is PortState.Open or PortState.Closed)) methods |= DiscoveryMethod.TcpConnect;

        var open = tcp.Where(t => t.result.State == PortState.Open).Select(t => t.port).ToList();
        return new LivenessResult(methods != DiscoveryMethod.None, methods, rtt, ttl, open);
    }

    private static Socket CreateSocket(IPAddress address) =>
        new(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };

    /// <summary>
    /// Ends a connection with FIN, never RST. Measured on a TP-Link TL-WR841N: one connection reset right after the
    /// handshake (SO_LINGER 0) made its UPnP web service stop answering for ~18 s, and its port-80 redirector for more
    /// than 10 minutes; a normal FIN close had no effect. TIME_WAIT only arises for open ports, so it stays small.
    /// Unread data must be drained first – Linux answers close() with RST while the receive buffer is not empty.
    /// </summary>
    internal static void CloseGracefully(Socket socket)
    {
        try
        {
            if (!socket.Connected) return;
            socket.Shutdown(SocketShutdown.Send);
            var buffer = new byte[4096];
            var drained = 0;
            while (socket.Available > 0 && drained < 256 * 1024)
            {
                var read = socket.Receive(buffer, SocketFlags.None);
                if (read <= 0) break;
                drained += read;
            }
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    /// <summary>TcpClient whose disposal closes with FIN (see <see cref="CloseGracefully"/>), including on streams wrapped by TLS.</summary>
    private sealed class GracefulTcpClient(AddressFamily family) : TcpClient(family)
    {
        protected override void Dispose(bool disposing)
        {
            if (disposing && Client is { } socket) CloseGracefully(socket);
            base.Dispose(disposing);
        }
    }
}
