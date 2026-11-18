using System.Buffers.Binary;
using System.Text;
using Weles.Core.Models;

namespace Weles.Core.Rules;

/// <summary>
/// Android Debug Bridge over TCP. WELES sends only the CNXN greeting (the first step of "adb connect") and reads the reply.
/// It never answers an AUTH challenge and never sends a public key, so no authorization prompt appears on the device
/// and no session is established.
/// </summary>
public static class AdbHandshake
{
    private const uint Cnxn = 0x4E584E43;
    private const uint Auth = 0x48545541;

    public static byte[] BuildConnect()
    {
        var payload = Encoding.ASCII.GetBytes("host::\0");
        var packet = new byte[24 + payload.Length];
        var span = packet.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(span, Cnxn);
        BinaryPrimitives.WriteUInt32LittleEndian(span[4..], 0x01000001);   // protocol version
        BinaryPrimitives.WriteUInt32LittleEndian(span[8..], 256 * 1024);   // max payload
        BinaryPrimitives.WriteUInt32LittleEndian(span[12..], (uint)payload.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(span[16..], (uint)payload.Sum(b => b));
        BinaryPrimitives.WriteUInt32LittleEndian(span[20..], Cnxn ^ 0xFFFFFFFF);
        payload.CopyTo(span[24..]);
        return packet;
    }

    public static ServiceIdentification? Parse(byte[] response)
    {
        if (response.Length < 24) return null;
        var command = BinaryPrimitives.ReadUInt32LittleEndian(response);
        var magic = BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(20));
        if (magic != (command ^ 0xFFFFFFFF) || command is not (Cnxn or Auth)) return null;

        var id = new ServiceIdentification
        {
            ServiceName = "adb",
            Product = "Android Debug Bridge",
            Confidence = 95,
            Method = "adb-handshake",
            OsHint = "Android",
            Extra = { ["adb.auth"] = command == Auth ? "required" : "none" }
        };

        if (command == Cnxn)
        {
            var length = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(12)), (uint)(response.Length - 24));
            var banner = BannerParser.Sanitize(Encoding.ASCII.GetString(response, 24, Math.Max(0, length)));
            id = id with { Banner = banner };
            foreach (var part in banner.Split(';', ':'))
            {
                var kv = part.Split('=', 2);
                if (kv.Length != 2) continue;
                switch (kv[0])
                {
                    case "ro.product.model": id.Extra["adb.model"] = kv[1]; break;
                    case "ro.product.name": id.Extra["adb.product"] = kv[1]; break;
                    case "ro.product.device": id.Extra["adb.device"] = kv[1]; break;
                }
            }
        }

        return id;
    }
}
