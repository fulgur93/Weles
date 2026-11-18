using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Weles.Tests.Support;

/// <summary>Minimal TCP server on 127.0.0.1 used to exercise the real probes.</summary>
public sealed class FakeServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public FakeServer(Func<Stream, CancellationToken, Task> handler, X509Certificate2? tlsCertificate = null)
    {
        _listener.Start();
        _loop = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await _listener.AcceptTcpClientAsync(_cts.Token); }
                catch (OperationCanceledException) { return; }
                catch (SocketException) { return; }

                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try
                        {
                            Stream stream = client.GetStream();
                            if (tlsCertificate is not null)
                            {
                                var ssl = new SslStream(stream);
                                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = tlsCertificate }, _cts.Token);
                                stream = ssl;
                            }

                            await handler(stream, _cts.Token);
                        }
                        catch (Exception) when (_cts.IsCancellationRequested || true)
                        {
                            // Probes disconnect abruptly by design.
                        }
                    }
                });
            }
        });
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public static FakeServer Banner(string banner) => new(async (s, ct) =>
    {
        await s.WriteAsync(Encoding.ASCII.GetBytes(banner), ct);
        await Task.Delay(3000, ct);
    });

    public static FakeServer Http(string response, X509Certificate2? cert = null) => new(async (s, ct) =>
    {
        var buffer = new byte[4096];
        var read = await s.ReadAsync(buffer, ct);
        if (read > 0 && Encoding.ASCII.GetString(buffer, 0, read).StartsWith("GET ", StringComparison.Ordinal))
        {
            await s.WriteAsync(Encoding.ASCII.GetBytes(response), ct);
        }
    }, cert);

    /// <summary>Replies to each request chunk using the responder; silent until the client speaks.</summary>
    public static FakeServer RequestResponse(Func<byte[], byte[]?> responder) => new(async (s, ct) =>
    {
        var buffer = new byte[4096];
        while (true)
        {
            var read = await s.ReadAsync(buffer, ct);
            if (read == 0) return;
            if (responder(buffer[..read]) is { } reply) await s.WriteAsync(reply, ct);
        }
    });

    /// <summary>Accepts and never speaks.</summary>
    public static FakeServer Silent() => new(async (s, ct) => await Task.Delay(Timeout.Infinite, ct));

    public static X509Certificate2 SelfSignedCertificate(string name = "weles-test.local", int validDays = 10)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(name);
        request.CertificateExtensions.Add(san.Build());
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(validDays));
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12), null);
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _listener.Stop();
        try { await _loop; } catch (OperationCanceledException) { }
        _cts.Dispose();
    }
}
