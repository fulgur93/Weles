using System.Net;
using System.Text;
using Weles.Infrastructure.Scanning;
using Weles.Tests.Support;

namespace Weles.Tests.Scanning;

public class ServiceProberTests
{
    private static readonly ScanOptions FastOptions = new() { ConnectTimeoutMs = 1000, BannerTimeoutMs = 600, ProbeTimeoutMs = 1500 };
    private static readonly ServiceProber Prober = new(FastOptions);

    private static Task<ServiceProbeResult> Probe(int port, string? hostname = null) =>
        Prober.ProbeAsync(IPAddress.Loopback, port, hostname, CancellationToken.None);

    [Fact]
    public async Task Ssh_banner_is_identified_with_version()
    {
        await using var server = FakeServer.Banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n");
        var result = await Probe(server.Port);

        Assert.Equal("OpenSSH", result.Identification.Product);
        Assert.Equal("9.6p1", result.Identification.Version);
        Assert.Equal("banner", result.Identification.Method);
    }

    [Fact]
    public async Task Http_server_is_identified_via_get_request()
    {
        await using var server = FakeServer.Http("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 30\r\n\r\n<title>Router admin login</title>");
        var result = await Probe(server.Port);

        Assert.Equal("http", result.Identification.ServiceName);
        Assert.Equal(("nginx", "1.18.0"), (result.Identification.Product, result.Identification.Version));
        Assert.Equal("Router admin login", result.Identification.Extra["http.title"]);
    }

    [Fact]
    public async Task Tls_service_certificate_is_captured_and_http_over_tls_identified()
    {
        using var cert = FakeServer.SelfSignedCertificate("nas.weles.test", validDays: 10);
        await using var server = FakeServer.Http("HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Debian)\r\n\r\n<title>NAS</title>", cert);

        var result = await Probe(server.Port, hostname: "nas.weles.test");

        Assert.True(result.Identification.IsTls);
        Assert.Equal("https", result.Identification.ServiceName);
        Assert.Equal("Apache httpd", result.Identification.Product);
        Assert.NotNull(result.Certificate);
        Assert.True(result.Certificate!.IsSelfSigned);
        Assert.True(result.Certificate.HostnameMatches);
        Assert.Contains("nas.weles.test", result.Certificate.SubjectAlternativeNames);
        Assert.Equal(2048, result.Certificate.KeySize);
        Assert.InRange((result.Certificate.NotAfter - DateTime.UtcNow).TotalDays, 8, 11);
        Assert.True(result.Identification.Extra.ContainsKey("tls.validation")); // self-signed is not trusted
    }

    [Fact]
    public async Task Certificate_hostname_mismatch_is_detected()
    {
        using var cert = FakeServer.SelfSignedCertificate("other.example");
        await using var server = FakeServer.Http("HTTP/1.1 200 OK\r\n\r\n", cert);

        var result = await Probe(server.Port, hostname: "nas.weles.test");

        Assert.False(result.Certificate!.HostnameMatches);
    }

    [Fact]
    public async Task Postgres_is_recognised_by_ssl_request_without_authentication()
    {
        await using var server = FakeServer.RequestResponse(req => req is [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F] ? "N"u8.ToArray() : null);
        var id = await Prober.ProbeProtocolAsync("postgresql", IPAddress.Loopback, server.Port, CancellationToken.None);

        Assert.Equal("PostgreSQL", id!.Product);
        Assert.Equal("not-supported", id.Extra["postgresql.ssl"]);
        Assert.Null(id.Version); // the SSLRequest exchange does not reveal a version – none is invented
    }

    [Fact]
    public async Task Unauthenticated_redis_reports_version_and_missing_auth()
    {
        await using var server = FakeServer.RequestResponse(req => Encoding.ASCII.GetString(req) switch
        {
            "PING\r\n" => "+PONG\r\n"u8.ToArray(),
            "INFO server\r\n" => Encoding.ASCII.GetBytes("$60\r\n# Server\r\nredis_version:6.0.16\r\nos:Linux 5.15.0 x86_64\r\n"),
            _ => null
        });

        var id = await Prober.ProbeProtocolAsync("redis", IPAddress.Loopback, server.Port, CancellationToken.None);

        Assert.Equal(("Redis", "6.0.16", "none"), (id!.Product, id.Version, id.Extra["redis.auth"]));
        Assert.Equal("Linux", id.OsHint);
    }

    [Fact]
    public async Task Redis_requiring_auth_is_not_queried_further()
    {
        var requests = new List<string>();
        await using var server = FakeServer.RequestResponse(req =>
        {
            lock (requests) requests.Add(Encoding.ASCII.GetString(req));
            return "-NOAUTH Authentication required.\r\n"u8.ToArray();
        });

        var id = await Prober.ProbeProtocolAsync("redis", IPAddress.Loopback, server.Port, CancellationToken.None);

        Assert.Equal("required", id!.Extra["redis.auth"]);
        Assert.Equal(["PING\r\n"], requests);
    }

    [Theory]
    [InlineData(2, "NLA (CredSSP)")]
    [InlineData(1, "TLS without NLA")]
    [InlineData(0, "standard RDP security")]
    public async Task Rdp_negotiation_reports_security_layer(byte selected, string expected)
    {
        byte[] response = [0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0, 0, 0x12, 0x34, 0, 0x02, 0x00, 0x08, 0x00, selected, 0, 0, 0];
        await using var server = FakeServer.RequestResponse(req => req.Length >= 11 && req[5] == 0xE0 ? response : null);

        var id = await Prober.ProbeProtocolAsync("rdp", IPAddress.Loopback, server.Port, CancellationToken.None);

        Assert.Equal("rdp", id!.ServiceName);
        Assert.Equal(expected, id.Extra["rdp.security"]);
    }

    [Fact]
    public async Task Silent_service_falls_back_to_port_hint_without_product()
    {
        await using var server = FakeServer.Silent();
        var result = await Probe(server.Port);

        Assert.Equal("port-hint", result.Identification.Method);
        Assert.Null(result.Identification.Product);
        Assert.Null(result.Identification.Version);
    }

    [Fact]
    public async Task Unrecognised_banner_is_kept_but_not_interpreted()
    {
        await using var server = FakeServer.Banner("WELCOME TO MY CUSTOM DAEMON v7\r\n");
        var result = await Probe(server.Port);

        Assert.Equal("banner-unrecognized", result.Identification.Method);
        Assert.Contains("CUSTOM DAEMON", result.Identification.Banner);
        Assert.Null(result.Identification.Version);
    }

    [Fact]
    public async Task MySql_greeting_is_parsed()
    {
        var version = Encoding.ASCII.GetBytes("8.0.36");
        byte[] payload = [0x0A, .. version, 0, .. new byte[20]];
        byte[] packet = [(byte)payload.Length, 0, 0, 0, .. payload];
        await using var server = new FakeServer(async (s, ct) => { await s.WriteAsync(packet, ct); await Task.Delay(2000, ct); });

        var result = await Probe(server.Port);

        Assert.Equal(("MySQL", "8.0.36"), (result.Identification.Product, result.Identification.Version));
    }

    [Fact]
    public async Task Icmp_ping_of_loopback_works_without_administrator_rights()
    {
        // Regression: a custom payload made every ping fail on unprivileged Linux.
        var (success, _, _) = await NetworkProbe.PingAsync(IPAddress.Loopback, 2000);
        Assert.True(success);
    }

    [Fact]
    public async Task Same_host_redirect_is_followed_once_to_read_the_title()
    {
        var paths = new List<string>();
        await using var server = new FakeServer(async (s, ct) =>
        {
            var buf = new byte[4096];
            var read = await s.ReadAsync(buf, ct);
            var path = Encoding.ASCII.GetString(buf, 0, read).Split(' ')[1];
            lock (paths) paths.Add(path);
            var reply = path == "/"
                ? "HTTP/1.0 302 Redirect\r\nServer: Http Server\r\nLocation: /main.html\r\n\r\n"
                : "HTTP/1.0 302 Again\r\nLocation: /third.html\r\n\r\n<title>Main page</title>";
            await s.WriteAsync(Encoding.ASCII.GetBytes(reply), ct);
        });

        var result = await Probe(server.Port);

        Assert.Equal("Main page", result.Identification.Extra["http.title"]);
        Assert.Equal(["/", "/main.html"], paths); // exactly one hop
    }

    [Fact]
    public async Task Redirect_to_another_host_is_not_followed()
    {
        var requests = 0;
        await using var server = FakeServer.RequestResponse(_ =>
        {
            Interlocked.Increment(ref requests);
            return "HTTP/1.1 301 Moved\r\nLocation: http://evil.example/\r\n\r\n"u8.ToArray();
        });

        var result = await Probe(server.Port);

        Assert.Equal("http://evil.example/", result.Identification.Extra["http.location"]);
        Assert.Equal(1, requests);
    }

    [Fact]
    public async Task Dns_over_tcp_is_confirmed_with_version_query()
    {
        await using var server = FakeServer.RequestResponse(req =>
            req.Length > 14 ? Weles.Tests.Core.DnsVersionProbeTests.Response(req, 0, "dnsmasq-2.90") : null);

        var id = await Prober.ProbeProtocolAsync("dns", IPAddress.Loopback, server.Port, CancellationToken.None);

        Assert.Equal(("dns", "dnsmasq", "2.90"), (id!.ServiceName, id.Product, id.Version));
        Assert.Equal("cpe:2.3:a:thekelleys:dnsmasq:2.90:*:*:*:*:*:*:*", id.Cpe);
    }
}
