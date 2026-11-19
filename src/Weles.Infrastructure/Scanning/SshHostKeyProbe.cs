using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Weles.Infrastructure.Scanning;

/// <summary>Public host key of an SSH server, as <c>ssh-keygen -l</c> prints it ("SHA256:…").</summary>
public sealed record SshHostKey(string Type, string Fingerprint);

/// <summary>
/// Reads the server's public host key the way <c>ssh-keyscan</c> does: identification line, KEXINIT and the first key
/// exchange message, then the connection is closed. No authentication is attempted – the host key is sent to every
/// client before login. The key identifies the operating system installation, so the same key on two addresses means
/// one device with two interfaces (e.g. Raspberry Pi on cable and Wi‑Fi).
/// </summary>
public static class SshHostKeyProbe
{
    public const string ClientIdentification = "SSH-2.0-WELES_Discovery";

    // Offered in preference order; the server picks the first one of ours it supports.
    internal static readonly string[] KexAlgorithms = ["ecdh-sha2-nistp256", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"];
    internal static readonly string[] HostKeyAlgorithms = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"];
    private const string Ciphers = "aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-cbc,aes256-cbc,3des-cbc";
    private const string Macs = "hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha2-256-etm@openssh.com,umac-64@openssh.com";

    private const byte MsgKexInit = 20;
    private const byte MsgKexDhInit = 30;   // same number for ECDH_INIT
    private const byte MsgKexDhReply = 31;  // same number for ECDH_REPLY
    private const int MaxPacket = 64 * 1024;

    /// <summary>RFC 3526 2048-bit MODP group (group 14), generator 2.</summary>
    private static readonly BigInteger Group14Prime = BigInteger.Parse(
        "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
        System.Globalization.NumberStyles.HexNumber);

    /// <summary>Runs the exchange on a fresh connection. Null when the server does not get that far (SSH-1, no common algorithm…).</summary>
    public static async Task<SshHostKey?> ReadAsync(Stream stream, int timeoutMs, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(timeoutMs);
        var reader = new PacketReader(stream);
        try
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes(ClientIdentification + "\r\n"), timeout.Token);
            if (!await reader.SkipIdentificationAsync(timeout.Token)) return null;
            await stream.WriteAsync(Packet(KexInit()), timeout.Token);

            byte[]? serverKexInit = null;
            while (serverKexInit is null)
            {
                var payload = await reader.NextPacketAsync(timeout.Token);
                if (payload is null) return null;
                if (payload[0] == MsgKexInit) serverKexInit = payload;
            }

            var serverKex = ReadNameLists(serverKexInit, 1)[0];
            var kex = KexAlgorithms.FirstOrDefault(serverKex.Contains);
            if (kex is null) return null;
            await stream.WriteAsync(Packet(KexInitMessage(kex)), timeout.Token);

            while (true)
            {
                var payload = await reader.NextPacketAsync(timeout.Token);
                if (payload is null) return null;
                if (payload[0] == MsgKexDhReply) return ParseReply(payload);
            }
        }
        catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException or FormatException or ArgumentException ||
                                   (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            return null;
        }
    }

    internal static byte[] KexInit()
    {
        var w = new MemoryStream();
        w.WriteByte(MsgKexInit);
        w.Write(RandomNumberGenerator.GetBytes(16));
        foreach (var list in (string[])[string.Join(',', KexAlgorithms), string.Join(',', HostKeyAlgorithms), Ciphers, Ciphers, Macs, Macs, "none,zlib@openssh.com", "none,zlib@openssh.com", "", ""])
        {
            WriteString(w, Encoding.ASCII.GetBytes(list));
        }

        w.WriteByte(0);          // first_kex_packet_follows
        w.Write(new byte[4]);    // reserved
        return w.ToArray();
    }

    /// <summary>Our half of the key exchange – only needed so the server sends its reply with the host key.</summary>
    internal static byte[] KexInitMessage(string kex)
    {
        var w = new MemoryStream();
        w.WriteByte(MsgKexDhInit);
        if (kex == "ecdh-sha2-nistp256")
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var p = ecdh.ExportParameters(false).Q;
            WriteString(w, [0x04, .. p.X!, .. p.Y!]);
        }
        else
        {
            var x = new BigInteger(RandomNumberGenerator.GetBytes(32), isUnsigned: true);
            WriteString(w, BigInteger.ModPow(2, x, Group14Prime).ToByteArray(isUnsigned: false, isBigEndian: true)); // mpint e
        }

        return w.ToArray();
    }

    internal static SshHostKey? ParseReply(byte[] payload)
    {
        var offset = 1;
        var blob = ReadString(payload, ref offset);
        var typeOffset = 0;
        var type = Encoding.ASCII.GetString(ReadString(blob, ref typeOffset));
        if (type.Length == 0 || type.Length > 64) return null;
        return new SshHostKey(type, Fingerprint(blob));
    }

    /// <summary>OpenSSH fingerprint: SHA-256 of the key blob, Base64 without padding.</summary>
    public static string Fingerprint(byte[] keyBlob) => "SHA256:" + Convert.ToBase64String(SHA256.HashData(keyBlob)).TrimEnd('=');

    /// <summary>Unencrypted binary packet (RFC 4253 §6): length, padding length, payload, ≥ 4 bytes padding to a multiple of 8.</summary>
    internal static byte[] Packet(byte[] payload)
    {
        var padding = 8 - (payload.Length + 5) % 8;
        if (padding < 4) padding += 8;
        var packet = new byte[4 + 1 + payload.Length + padding];
        BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)(1 + payload.Length + padding));
        packet[4] = (byte)padding;
        payload.CopyTo(packet, 5);
        RandomNumberGenerator.Fill(packet.AsSpan(5 + payload.Length));
        return packet;
    }

    internal static List<string[]> ReadNameLists(byte[] kexInit, int offset)
    {
        offset += 16; // cookie
        var lists = new List<string[]>();
        for (var i = 0; i < 10; i++) lists.Add(Encoding.ASCII.GetString(ReadString(kexInit, ref offset)).Split(',', StringSplitOptions.RemoveEmptyEntries));
        return lists;
    }

    private static void WriteString(Stream w, byte[] value)
    {
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)value.Length);
        w.Write(len);
        w.Write(value);
    }

    private static byte[] ReadString(byte[] data, ref int offset)
    {
        if (offset + 4 > data.Length) throw new FormatException("SSH string truncated");
        var len = (int)BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset));
        if (len < 0 || offset + 4 + len > data.Length) throw new FormatException("SSH string length out of range");
        var value = data.AsSpan(offset + 4, len).ToArray();
        offset += 4 + len;
        return value;
    }

    private sealed class PacketReader(Stream stream)
    {
        private readonly byte[] _buffer = new byte[MaxPacket + 64];
        private int _start;
        private int _end;

        /// <summary>Lines before "SSH-" are allowed by RFC 4253; protocol 1.x servers cannot do this exchange.</summary>
        public async Task<bool> SkipIdentificationAsync(CancellationToken ct)
        {
            for (var lines = 0; lines < 20; lines++)
            {
                var line = await ReadLineAsync(ct);
                if (line is null) return false;
                if (line.StartsWith("SSH-", StringComparison.Ordinal)) return line.StartsWith("SSH-2.0-", StringComparison.Ordinal) || line.StartsWith("SSH-1.99-", StringComparison.Ordinal);
            }

            return false;
        }

        public async Task<byte[]?> NextPacketAsync(CancellationToken ct)
        {
            if (!await FillAsync(4, ct)) return null;
            var length = (int)BinaryPrimitives.ReadUInt32BigEndian(_buffer.AsSpan(_start));
            if (length < 5 || length > MaxPacket) return null;
            if (!await FillAsync(4 + length, ct)) return null;
            var padding = _buffer[_start + 4];
            var payloadLength = length - 1 - padding;
            if (payloadLength < 1) return null;
            var payload = _buffer.AsSpan(_start + 5, payloadLength).ToArray();
            _start += 4 + length;
            return payload;
        }

        private async Task<string?> ReadLineAsync(CancellationToken ct)
        {
            while (true)
            {
                var newline = Array.IndexOf(_buffer, (byte)'\n', _start, _end - _start);
                if (newline >= 0)
                {
                    var line = Encoding.ASCII.GetString(_buffer, _start, newline - _start).TrimEnd('\r');
                    _start = newline + 1;
                    return line;
                }

                if (_end - _start > 512 || !await ReadMoreAsync(ct)) return null;
            }
        }

        private async Task<bool> FillAsync(int count, CancellationToken ct)
        {
            while (_end - _start < count)
            {
                if (!await ReadMoreAsync(ct)) return false;
            }

            return true;
        }

        private async Task<bool> ReadMoreAsync(CancellationToken ct)
        {
            if (_start > 0)
            {
                Array.Copy(_buffer, _start, _buffer, 0, _end - _start);
                _end -= _start;
                _start = 0;
            }

            if (_end == _buffer.Length) return false;
            var read = await stream.ReadAsync(_buffer.AsMemory(_end), ct);
            if (read == 0) return false;
            _end += read;
            return true;
        }
    }
}
