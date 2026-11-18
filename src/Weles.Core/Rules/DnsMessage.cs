using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Weles.Core.Rules;

public sealed record DnsRecord(string Name, ushort Type, uint Ttl, string? Target = null, ushort? Port = null, IPAddress? Address = null, IReadOnlyList<string>? Texts = null);

/// <summary>Minimal DNS message reader/writer (PTR, SRV, TXT, A, AAAA) used for mDNS / DNS-SD. Input is untrusted.</summary>
public static class DnsMessage
{
    public const ushort TypeA = 1, TypePtr = 12, TypeTxt = 16, TypeAaaa = 28, TypeSrv = 33;

    public static byte[] BuildQuery(ushort id, IEnumerable<(string Name, ushort Type)> questions)
    {
        var q = questions.ToList();
        var buffer = new List<byte>(512);
        var header = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header, id);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), (ushort)q.Count);
        buffer.AddRange(header);
        foreach (var (name, type) in q)
        {
            foreach (var label in name.TrimEnd('.').Split('.'))
            {
                var bytes = Encoding.UTF8.GetBytes(label);
                buffer.Add((byte)Math.Min(bytes.Length, 63));
                buffer.AddRange(bytes.Take(63));
            }

            buffer.Add(0);
            buffer.AddRange([(byte)(type >> 8), (byte)type, 0x00, 0x01]); // class IN
        }

        return [.. buffer];
    }

    /// <summary>Parses a response; returns all answer, authority and additional records.</summary>
    public static bool TryParse(byte[] msg, out ushort id, out List<DnsRecord> records)
    {
        records = [];
        id = 0;
        if (msg.Length < 12) return false;
        id = BinaryPrimitives.ReadUInt16BigEndian(msg);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(2));
        if ((flags & 0x8000) == 0) return false;

        var qd = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(4));
        var total = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(6)) + BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(8)) + BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(10));
        var offset = 12;
        try
        {
            for (var i = 0; i < qd; i++)
            {
                ReadName(msg, ref offset);
                offset += 4;
            }

            for (var i = 0; i < total && i < 512; i++)
            {
                var name = ReadName(msg, ref offset);
                if (offset + 10 > msg.Length) return records.Count > 0;
                var type = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(offset));
                var ttl = BinaryPrimitives.ReadUInt32BigEndian(msg.AsSpan(offset + 4));
                var length = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(offset + 8));
                offset += 10;
                var end = offset + length;
                if (end > msg.Length) return records.Count > 0;

                var rdataOffset = offset;
                DnsRecord? record = type switch
                {
                    TypePtr => new DnsRecord(name, type, ttl, Target: ReadName(msg, ref rdataOffset)),
                    TypeSrv when length >= 7 => new DnsRecord(name, type, ttl,
                        Port: BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(offset + 4)),
                        Target: ReadName(msg, ref Advance(ref rdataOffset, 6))),
                    TypeA when length == 4 => new DnsRecord(name, type, ttl, Address: new IPAddress(msg.AsSpan(offset, 4))),
                    TypeAaaa when length == 16 => new DnsRecord(name, type, ttl, Address: new IPAddress(msg.AsSpan(offset, 16))),
                    TypeTxt => new DnsRecord(name, type, ttl, Texts: ReadTexts(msg, offset, end)),
                    _ => null
                };
                if (record is not null) records.Add(record);
                offset = end;
            }
        }
        catch (FormatException)
        {
            return records.Count > 0;
        }

        return true;
    }

    private static ref int Advance(ref int offset, int by)
    {
        offset += by;
        return ref offset;
    }

    private static List<string> ReadTexts(byte[] msg, int offset, int end)
    {
        var texts = new List<string>();
        while (offset < end)
        {
            var len = msg[offset++];
            if (offset + len > end) break;
            texts.Add(BannerParser.Sanitize(Encoding.UTF8.GetString(msg, offset, len)));
            offset += len;
        }

        return texts;
    }

    /// <summary>Reads a possibly compressed name. Pointer loops and overruns raise FormatException.</summary>
    public static string ReadName(byte[] msg, ref int offset)
    {
        var labels = new List<string>();
        var position = offset;
        var jumped = false;
        for (var guard = 0; guard < 128; guard++)
        {
            if (position >= msg.Length) throw new FormatException("Name overruns message");
            var len = msg[position];
            if (len == 0)
            {
                if (!jumped) offset = position + 1;
                return string.Join('.', labels);
            }

            if ((len & 0xC0) == 0xC0)
            {
                if (position + 1 >= msg.Length) throw new FormatException("Truncated pointer");
                if (!jumped) offset = position + 2;
                position = (len & 0x3F) << 8 | msg[position + 1];
                jumped = true;
                continue;
            }

            if (position + 1 + len > msg.Length) throw new FormatException("Label overruns message");
            labels.Add(Encoding.UTF8.GetString(msg, position + 1, len));
            position += len + 1;
        }

        throw new FormatException("Name too long or pointer loop");
    }
}
