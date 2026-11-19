using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Weles.Core.Models;
using Weles.Core.Networking;
using Weles.Core.Rules;

namespace Weles.Infrastructure.Scanning;

public sealed record ServiceProbeResult(ServiceIdentification Identification, CertificateSnapshot? Certificate);

/// <summary>
/// Identifies the service behind an open TCP port using non-intrusive probes only:
/// passive banner read, protocol greetings (Redis PING, PostgreSQL SSLRequest, RDP negotiation),
/// one HTTP GET and a TLS handshake. No authentication attempts, no exploitation.
/// </summary>
public sealed partial class ServiceProber(ScanOptions options)
{
    public const string UserAgent = "WELES-Discovery/0.2 (authorized security audit)";
    private const int MaxResponseBytes = 64 * 1024;

    public async Task<ServiceProbeResult> ProbeAsync(IPAddress address, int port, string? hostname, CancellationToken cancellationToken)
    {
        var tlsTried = false;
        if (WellKnownPorts.ImplicitTlsPorts.Contains(port))
        {
            tlsTried = true;
            if (await TryTlsAsync(address, port, hostname, cancellationToken) is { } tls) return tls;
        }

        byte[] banner = await ReadBannerAsync(address, port, cancellationToken);
        if (banner.Length > 0)
        {
            if (banner[0] == 0x15 && banner.Length >= 3 && banner[1] == 0x03 && !tlsTried)
            {
                if (await TryTlsAsync(address, port, hostname, cancellationToken) is { } tlsAfterAlert) return tlsAfterAlert;
            }

            // Some embedded servers answer before receiving a request (e.g. a TP-Link router pushes "301 Moved" on connect).
            if (PushedHttpResponse(banner) is { } pushed)
            {
                return new ServiceProbeResult(HttpFingerprinter.Identify(pushed, isTls: false) with { Method = "http-banner" }, null);
            }

            if (BannerParser.Parse(banner, port) is { } fromBanner)
            {
                // SSH: the public host key identifies the installation – the same key on two addresses is one device.
                if (fromBanner.ServiceName == "ssh" && await ReadSshHostKeyAsync(address, port, cancellationToken) is { } key)
                {
                    fromBanner.Extra["ssh.hostKey"] = key.Fingerprint;
                    fromBanner.Extra["ssh.hostKeyType"] = key.Type;
                }

                return new ServiceProbeResult(fromBanner, null);
            }
        }

        if (banner.Length == 0)
        {
            var active = ProtocolProbePorts.TryGetValue(port, out var protocol)
                ? await ProbeProtocolAsync(protocol, address, port, cancellationToken)
                : null;
            if (active is not null) return new ServiceProbeResult(active, null);

            if (await TryHttpAsync(address, port, hostname, cancellationToken) is { } http) return new ServiceProbeResult(http, null);

            if (!tlsTried && await TryTlsAsync(address, port, hostname, cancellationToken) is { } tls) return tls;
        }

        if (banner.Length > 0)
        {
            var fallback = ServiceIdentification.FromPortOnly(port);
            return new ServiceProbeResult(fallback with { Banner = BannerParser.Printable(banner), Method = "banner-unrecognized", Confidence = Math.Max(fallback.Confidence, 25) }, null);
        }

        return new ServiceProbeResult(ServiceIdentification.FromPortOnly(port), null);
    }

    internal static HttpResponseInfo? PushedHttpResponse(byte[] banner)
    {
        var length = banner.Length;
        while (length > 0 && banner[length - 1] == 0) length--; // NUL padding after the response
        return HttpResponseParser.TryParse(banner[..length], out var response) ? response : null;
    }

    /// <summary>Client-speaks-first protocols probed only on their registered ports, to avoid sending foreign bytes to unknown services.</summary>
    private static readonly Dictionary<int, string> ProtocolProbePorts = new() { [6379] = "redis", [5432] = "postgresql", [3389] = "rdp", [53] = "dns", [5555] = "adb" };

    internal Task<ServiceIdentification?> ProbeProtocolAsync(string protocol, IPAddress address, int port, CancellationToken ct) => protocol switch
    {
        "redis" => ProbeRedisAsync(address, port, ct),
        "postgresql" => ProbePostgresAsync(address, port, ct),
        "rdp" => ProbeRdpAsync(address, port, ct),
        "dns" => ProbeDnsAsync(address, port, ct),
        "adb" => ProbeAdbAsync(address, port, ct),
        _ => Task.FromResult<ServiceIdentification?>(null)
    };

    private async Task<byte[]> ReadBannerAsync(IPAddress address, int port, CancellationToken ct)
    {
        using var client = await NetworkProbe.OpenAsync(address, port, options.ConnectTimeoutMs, ct);
        if (client is null) return [];
        return await ReadAsync(client.GetStream(), options.BannerTimeoutMs, 4096, ct);
    }

    private async Task<SshHostKey?> ReadSshHostKeyAsync(IPAddress address, int port, CancellationToken ct)
    {
        using var client = await NetworkProbe.OpenAsync(address, port, options.ConnectTimeoutMs, ct);
        return client is null ? null : await SshHostKeyProbe.ReadAsync(client.GetStream(), options.ProbeTimeoutMs, ct);
    }

    private async Task<ServiceIdentification?> ProbeRedisAsync(IPAddress address, int port, CancellationToken ct)
    {
        using var client = await NetworkProbe.OpenAsync(address, port, options.ConnectTimeoutMs, ct);
        if (client is null) return null;
        var stream = client.GetStream();
        var pong = Encoding.ASCII.GetString(await ExchangeAsync(stream, "PING\r\n"u8.ToArray(), ct));
        if (pong.StartsWith("-NOAUTH", StringComparison.Ordinal) || pong.StartsWith("-DENIED", StringComparison.Ordinal) || pong.StartsWith("-ERR", StringComparison.Ordinal))
        {
            return new ServiceIdentification
            {
                ServiceName = "redis", Product = "Redis", Vendor = "redis", Confidence = 85, Method = "redis-ping",
                Banner = BannerParser.Sanitize(pong), Extra = { ["redis.auth"] = "required" }
            };
        }

        if (!pong.StartsWith("+PONG", StringComparison.Ordinal)) return null;

        // Unauthenticated instance: INFO server is a read-only metadata command (no data access, no login attempt).
        var info = Encoding.ASCII.GetString(await ExchangeAsync(stream, "INFO server\r\n"u8.ToArray(), ct));
        var version = RedisVersion().Match(info) is { Success: true } m ? m.Groups[1].Value : null;
        var os = RedisOs().Match(info) is { Success: true } o ? o.Groups[1].Value.Trim() : null;
        var id = new ServiceIdentification
        {
            ServiceName = "redis", Product = "Redis", Vendor = "redis", Version = version, Cpe = ProductCatalog.Cpe("Redis", version),
            Confidence = version is null ? 85 : 95, Method = "redis-ping", Banner = "+PONG",
            OsHint = os is null ? null : os.StartsWith("Linux", StringComparison.OrdinalIgnoreCase) ? "Linux" : os,
            Extra = { ["redis.auth"] = "none" }
        };
        return id;
    }

    private async Task<ServiceIdentification?> ProbePostgresAsync(IPAddress address, int port, CancellationToken ct)
    {
        using var client = await NetworkProbe.OpenAsync(address, port, options.ConnectTimeoutMs, ct);
        if (client is null) return null;
        var response = await ExchangeAsync(client.GetStream(), [0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F], ct);
        if (response.Length != 1 || response[0] is not ((byte)'S' or (byte)'N')) return null;
        return new ServiceIdentification
        {
            ServiceName = "postgresql", Product = "PostgreSQL", Vendor = "postgresql", Confidence = 85, Method = "postgres-sslrequest",
            Extra = { ["postgresql.ssl"] = response[0] == (byte)'S' ? "supported" : "not-supported" }
        };
    }

    private async Task<ServiceIdentification?> ProbeRdpAsync(IPAddress address, int port, CancellationToken ct)
    {
        using var client = await NetworkProbe.OpenAsync(address, port, options.ConnectTimeoutMs, ct);
        if (client is null) return null;
        // X.224 Connection Request with RDP_NEG_REQ asking for TLS | CredSSP.
        byte[] request = [0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00];
        var r = await ExchangeAsync(client.GetStream(), request, ct);
        if (r.Length < 11 || r[0] != 0x03 || r[5] != 0xD0) return null;

        var security = "standard RDP security";
        if (r.Length >= 19 && r[11] == 0x02)
        {
            var selected = BitConverter.ToUInt32(r, 15);
            security = selected switch
            {
                0 => "standard RDP security",
                1 => "TLS without NLA",
                2 or 8 => "NLA (CredSSP)",
                _ => $"protocol 0x{selected:x}"
            };
        }
        else if (r.Length >= 19 && r[11] == 0x03)
        {
            security = "negotiation failure";
        }

        return new ServiceIdentification
        {
            ServiceName = "rdp", Product = "Remote Desktop Protocol", Confidence = 90, Method = "rdp-negotiation", OsHint = "Windows",
            Extra = { ["rdp.security"] = security }
        };
    }

    private async Task<ServiceIdentification?> ProbeAdbAsync(IPAddress address, int port, CancellationToken ct)
    {
        using var client = await NetworkProbe.OpenAsync(address, port, options.ConnectTimeoutMs, ct);
        if (client is null) return null;
        return AdbHandshake.Parse(await ExchangeAsync(client.GetStream(), AdbHandshake.BuildConnect(), ct));
    }

    private async Task<ServiceIdentification?> ProbeDnsAsync(IPAddress address, int port, CancellationToken ct)
    {
        using var client = await NetworkProbe.OpenAsync(address, port, options.ConnectTimeoutMs, ct);
        if (client is null) return null;
        var id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        return DnsVersionProbe.Parse(await ExchangeAsync(client.GetStream(), DnsVersionProbe.BuildQuery(id), ct), id);
    }

    private async Task<ServiceIdentification?> TryHttpAsync(IPAddress address, int port, string? hostname, CancellationToken ct)
    {
        var first = await HttpGetAsync(address, port, hostname, "/", ct);
        if (first is null) return null;
        var initial = HttpFingerprinter.Identify(first, isTls: false);
        if (RedirectPath(first, address, port, hostname, isTls: false) is not { } path) return initial;

        var target = await HttpGetAsync(address, port, hostname, path, ct);
        return target is null ? initial : HttpFingerprinter.CombineRedirect(initial, HttpFingerprinter.Identify(target, isTls: false));
    }

    private async Task<HttpResponseInfo?> HttpGetAsync(IPAddress address, int port, string? hostname, string path, CancellationToken ct)
    {
        using var client = await NetworkProbe.OpenAsync(address, port, options.ConnectTimeoutMs, ct);
        if (client is null) return null;
        var raw = await SendHttpRequestAsync(client.GetStream(), address, port, hostname, path, ct);
        return HttpResponseParser.TryParse(raw, out var response) ? response : null;
    }

    /// <summary>One redirect hop is followed, and only within the same scheme, host and port (the approved target).</summary>
    private static string? RedirectPath(HttpResponseInfo response, IPAddress address, int port, string? hostname, bool isTls) =>
        response.StatusCode is >= 300 and < 400
            ? HttpFingerprinter.SameOriginRedirectPath(response.Header("Location"), hostname is null ? [address.ToString()] : [address.ToString(), hostname], port, isTls)
            : null;

    private sealed class TlsSession(TcpClient client, SslStream stream, X509Certificate2? certificate, SslPolicyErrors errors) : IAsyncDisposable
    {
        public SslStream Stream => stream;
        public X509Certificate2? Certificate => certificate;
        public SslPolicyErrors Errors => errors;

        public async ValueTask DisposeAsync()
        {
            await stream.DisposeAsync();
            certificate?.Dispose();
            client.Dispose();
        }
    }

    private async Task<TlsSession?> OpenTlsAsync(IPAddress address, int port, string? hostname, CancellationToken ct)
    {
        var client = await NetworkProbe.OpenAsync(address, port, options.ConnectTimeoutMs, ct);
        if (client is null) return null;

        X509Certificate2? certificate = null;
        var policyErrors = SslPolicyErrors.None;
        var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(options.ProbeTimeoutMs);
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = hostname ?? address.ToString(),
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                // The certificate is recorded and assessed, never trusted: WELES does not send credentials.
                RemoteCertificateValidationCallback = (_, cert, _, errors) =>
                {
                    if (cert is not null) certificate ??= X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
                    policyErrors = errors;
                    return true;
                }
            }, timeout.Token);
            return new TlsSession(client, ssl, certificate, policyErrors);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or SocketException or System.ComponentModel.Win32Exception || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            await ssl.DisposeAsync();
            certificate?.Dispose();
            client.Dispose();
            return null;
        }
    }

    private async Task<ServiceProbeResult?> TryTlsAsync(IPAddress address, int port, string? hostname, CancellationToken ct)
    {
        await using var session = await OpenTlsAsync(address, port, hostname, ct);
        if (session is null) return null;

        var ssl = session.Stream;
        var snapshot = session.Certificate is null ? null : CertificateSnapshot.From(session.Certificate, hostname, ssl.SslProtocol.ToString(), ssl.NegotiatedCipherSuite.ToString(), session.Errors);

        ServiceIdentification identification;
        var raw = await SendHttpRequestAsync(ssl, address, port, hostname, "/", ct);
        if (HttpResponseParser.TryParse(raw, out var response))
        {
            identification = HttpFingerprinter.Identify(response, isTls: true, snapshot?.Subject);
            if (RedirectPath(response, address, port, hostname, isTls: true) is { } path)
            {
                await using var second = await OpenTlsAsync(address, port, hostname, ct);
                if (second is not null && HttpResponseParser.TryParse(await SendHttpRequestAsync(second.Stream, address, port, hostname, path, ct), out var target))
                {
                    identification = HttpFingerprinter.CombineRedirect(identification, HttpFingerprinter.Identify(target, isTls: true, snapshot?.Subject));
                }
            }
        }
        else
        {
            var hint = ServiceIdentification.FromPortOnly(port);
            identification = hint with { ServiceName = $"ssl/{hint.ServiceName}", IsTls = true, Method = "tls-handshake", Confidence = Math.Max(hint.Confidence, 40) };
        }

        identification.Extra["tls.protocol"] = ssl.SslProtocol.ToString();
        identification.Extra["tls.cipher"] = ssl.NegotiatedCipherSuite.ToString();
        if (session.Errors != SslPolicyErrors.None) identification.Extra["tls.validation"] = session.Errors.ToString();
        if (await AcceptsLegacyTlsAsync(address, port, hostname, ct)) identification.Extra["tls.legacy"] = "TLS 1.0/1.1 accepted";

        return new ServiceProbeResult(identification, snapshot);
    }

    /// <summary>
    /// True only when a TLS 1.0/1.1 handshake actually succeeds. A failure is inconclusive: the local OS crypto
    /// policy (e.g. OpenSSL security level) may refuse legacy protocols on the client side.
    /// </summary>
    private async Task<bool> AcceptsLegacyTlsAsync(IPAddress address, int port, string? hostname, CancellationToken ct)
    {
        using var client = await NetworkProbe.OpenAsync(address, port, options.ConnectTimeoutMs, ct);
        if (client is null) return false;
        await using var ssl = new SslStream(client.GetStream(), false, (_, _, _, _) => true);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(options.ProbeTimeoutMs);
        try
        {
#pragma warning disable SYSLIB0039 // Legacy protocols are requested deliberately, only to detect them.
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = hostname ?? address.ToString(),
                EnabledSslProtocols = SslProtocols.Tls | SslProtocols.Tls11,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, timeout.Token);
            return ssl.SslProtocol is SslProtocols.Tls or SslProtocols.Tls11;
#pragma warning restore SYSLIB0039
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or SocketException or NotSupportedException or System.ComponentModel.Win32Exception || ex is OperationCanceledException)
        {
            return false;
        }
    }

    private async Task<byte[]> SendHttpRequestAsync(Stream stream, IPAddress address, int port, string? hostname, string path, CancellationToken ct)
    {
        var host = hostname ?? (address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString());
        if (port is not (80 or 443)) host += $":{port}";
        var request = $"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UserAgent}\r\nAccept: text/html,*/*\r\nConnection: close\r\n\r\n";
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(options.ProbeTimeoutMs);
            await stream.WriteAsync(Encoding.ASCII.GetBytes(request), timeout.Token);
            return await ReadAsync(stream, options.ProbeTimeoutMs, MaxResponseBytes, ct);
        }
        catch (Exception ex) when (ex is IOException or SocketException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            return [];
        }
    }

    private async Task<byte[]> ExchangeAsync(Stream stream, byte[] request, CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(options.ProbeTimeoutMs);
            await stream.WriteAsync(request, timeout.Token);
            return await ReadAsync(stream, options.ProbeTimeoutMs, 8192, ct);
        }
        catch (Exception ex) when (ex is IOException or SocketException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            return [];
        }
    }

    /// <summary>Reads until the peer closes, the size limit is hit, or no data arrives for a short idle period after the first chunk.</summary>
    private static async Task<byte[]> ReadAsync(Stream stream, int firstByteTimeoutMs, int maxBytes, CancellationToken ct)
    {
        var buffer = new byte[Math.Min(maxBytes, 8192)];
        using var result = new MemoryStream();
        var waitMs = firstByteTimeoutMs;
        while (result.Length < maxBytes)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(waitMs);
            int read;
            try
            {
                read = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, maxBytes - result.Length)), timeout.Token);
            }
            catch (Exception ex) when (ex is IOException or SocketException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
            {
                break;
            }

            if (read == 0) break;
            result.Write(buffer, 0, read);
            waitMs = 400;
        }

        ct.ThrowIfCancellationRequested();
        return result.ToArray();
    }

    [GeneratedRegex(@"redis_version:([\d.]+)")] private static partial Regex RedisVersion();
    [GeneratedRegex(@"\nos:([^\r\n]+)")] private static partial Regex RedisOs();
}
