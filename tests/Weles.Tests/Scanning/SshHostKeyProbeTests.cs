using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Weles.Infrastructure.Scanning;
using Weles.Tests.Support;

namespace Weles.Tests.Scanning;

public class SshHostKeyProbeTests
{
    private static byte[] SshString(byte[] v)
    {
        var b = new byte[4 + v.Length];
        BinaryPrimitives.WriteUInt32BigEndian(b, (uint)v.Length);
        v.CopyTo(b, 4);
        return b;
    }

    private static byte[] HostKeyBlob(string type, byte[] key) => [.. SshString(Encoding.ASCII.GetBytes(type)), .. SshString(key)];

    /// <summary>A minimal SSH server: identification, KEXINIT, and the key exchange reply carrying its host key.</summary>
    private static FakeServer SshServer(byte[] hostKeyBlob, string kexAlgorithms, List<string> clientLines) => new(async (s, ct) =>
    {
        await s.WriteAsync("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"u8.ToArray(), ct);
        var kexInit = new List<byte> { 20 };
        kexInit.AddRange(new byte[16]);
        foreach (var list in new[] { kexAlgorithms, "ssh-ed25519", "aes128-ctr", "aes128-ctr", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", "" }) kexInit.AddRange(SshString(Encoding.ASCII.GetBytes(list)));
        kexInit.AddRange(new byte[5]);
        await s.WriteAsync(SshHostKeyProbe.Packet([.. kexInit]), ct);

        // Client identification line, then its KEXINIT and KEX_(EC)DH_INIT.
        var buffer = new byte[8192];
        var received = new MemoryStream();
        while (!Encoding.ASCII.GetString(received.ToArray()).Contains('\n'))
        {
            var n = await s.ReadAsync(buffer, ct);
            if (n == 0) return;
            received.Write(buffer, 0, n);
        }

        lock (clientLines) clientLines.Add(Encoding.ASCII.GetString(received.ToArray()).Split('\n')[0].TrimEnd('\r'));
        var packets = 0;
        var data = received.ToArray().AsSpan(Array.IndexOf(received.ToArray(), (byte)'\n') + 1).ToArray().ToList();
        while (packets < 2)
        {
            while (data.Count >= 4 && data.Count >= 4 + (int)BinaryPrimitives.ReadUInt32BigEndian(data.Take(4).ToArray()))
            {
                var len = (int)BinaryPrimitives.ReadUInt32BigEndian(data.Take(4).ToArray());
                var msg = data[5];
                lock (clientLines) clientLines.Add($"msg {msg}");
                data.RemoveRange(0, 4 + len);
                packets++;
            }

            if (packets >= 2) break;
            var n = await s.ReadAsync(buffer, ct);
            if (n == 0) return;
            data.AddRange(buffer.Take(n));
        }

        byte[] reply = [31, .. SshString(hostKeyBlob), .. SshString(new byte[65]), .. SshString(new byte[10])];
        await s.WriteAsync(SshHostKeyProbe.Packet(reply), ct);
        await Task.Delay(2000, ct);
    });

    [Theory]
    [InlineData("curve25519-sha256,ecdh-sha2-nistp256")]
    [InlineData("diffie-hellman-group14-sha1")]
    public async Task Host_key_is_read_without_authentication(string serverKex)
    {
        var blob = HostKeyBlob("ssh-ed25519", Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());
        var lines = new List<string>();
        await using var server = SshServer(blob, serverKex, lines);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, server.Port);

        var key = await SshHostKeyProbe.ReadAsync(client.GetStream(), 4000, CancellationToken.None);

        Assert.NotNull(key);
        Assert.Equal("ssh-ed25519", key.Type);
        Assert.Equal(SshHostKeyProbe.Fingerprint(blob), key.Fingerprint);
        Assert.StartsWith("SHA256:", key.Fingerprint);
        Assert.DoesNotContain("=", key.Fingerprint);
        // The client only identifies itself, proposes algorithms and starts the exchange – nothing else is sent.
        Assert.Equal([SshHostKeyProbe.ClientIdentification, "msg 20", "msg 30"], lines);
    }

    [Fact]
    public async Task No_common_algorithm_or_ssh1_gives_no_key()
    {
        var lines = new List<string>();
        await using (var server = SshServer(HostKeyBlob("ssh-rsa", [1, 2, 3]), "curve25519-sha256", lines))
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, server.Port);
            Assert.Null(await SshHostKeyProbe.ReadAsync(client.GetStream(), 3000, CancellationToken.None));
        }

        await using var ssh1 = FakeServer.Banner("SSH-1.5-OldServer\r\n");
        using var c1 = new TcpClient();
        await c1.ConnectAsync(IPAddress.Loopback, ssh1.Port);
        Assert.Null(await SshHostKeyProbe.ReadAsync(c1.GetStream(), 3000, CancellationToken.None));
    }

    [Fact]
    public void Fingerprint_matches_ssh_keygen_format()
    {
        // ssh-keygen -lf of an Ed25519 key with this blob prints this value.
        var blob = HostKeyBlob("ssh-ed25519", new byte[32]);
        Assert.Equal("SHA256:" + Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(blob)).TrimEnd('='), SshHostKeyProbe.Fingerprint(blob));
    }

    /// <summary>
    /// Real servers on a network the user approved: WELES_LIVE_SSH="host1,host2" WELES_LIVE_SSH_EXPECT="SHA256:…".
    /// Does nothing without the variables – the test suite never touches the network on its own.
    /// </summary>
    [Fact]
    public async Task Live_hosts_on_an_approved_network()
    {
        if (Environment.GetEnvironmentVariable("WELES_LIVE_SSH") is not { Length: > 0 } hosts) return;
        var expected = Environment.GetEnvironmentVariable("WELES_LIVE_SSH_EXPECT");
        foreach (var host in hosts.Split(','))
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Parse(host), 22);
            var key = await SshHostKeyProbe.ReadAsync(client.GetStream(), 5000, CancellationToken.None);
            Console.WriteLine($"LIVE {host}: {key?.Type} {key?.Fingerprint}");
            Assert.NotNull(key);
            if (expected is not null) Assert.Equal(expected, key.Fingerprint);
        }
    }
}
