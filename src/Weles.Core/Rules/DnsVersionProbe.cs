using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;
using Weles.Core.Models;

namespace Weles.Core.Rules;

/// <summary>
/// DNS over TCP identification with a single read-only query: "version.bind" TXT in class CHAOS.
/// Any well-formed DNS reply with the matching ID confirms the protocol; the version is reported only when the server discloses it.
/// </summary>
public static partial class DnsVersionProbe
{
    public static byte[] BuildQuery(ushort id)
    {
        var message = new List<byte>();
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header, id);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], 0x0000); // standard query, no recursion
        BinaryPrimitives.WriteUInt16BigEndian(header[4..], 1);      // QDCOUNT
        message.AddRange(header.ToArray());
        foreach (var label in new[] { "version", "bind" })
        {
            message.Add((byte)label.Length);
            message.AddRange(Encoding.ASCII.GetBytes(label));
        }

        message.Add(0);
        message.AddRange(new byte[] { 0x00, 0x10, 0x00, 0x03 }); // TXT, CHAOS
        var framed = new byte[message.Count + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Count);
        message.CopyTo(framed, 2);
        return framed;
    }

    public static ServiceIdentification? Parse(byte[] tcpResponse, ushort expectedId)
    {
        if (tcpResponse.Length < 14) return null;
        var msg = tcpResponse.AsSpan(2);
        var declared = BinaryPrimitives.ReadUInt16BigEndian(tcpResponse);
        if (declared < 12 || msg.Length < 12) return null;
        msg = msg[..Math.Min(msg.Length, declared)];

        if (BinaryPrimitives.ReadUInt16BigEndian(msg) != expectedId) return null;
        var flags = BinaryPrimitives.ReadUInt16BigEndian(msg[2..]);
        if ((flags & 0x8000) == 0) return null; // not a response

        var rcode = flags & 0x000F;
        var answers = BinaryPrimitives.ReadUInt16BigEndian(msg[6..]);
        string? version = null;
        if (rcode == 0 && answers > 0)
        {
            version = TryReadFirstTxt(msg, BinaryPrimitives.ReadUInt16BigEndian(msg[4..]));
        }

        var id = new ServiceIdentification
        {
            ServiceName = "dns",
            Confidence = 85,
            Method = "dns-version-query",
            Extra = { ["dns.rcode"] = RcodeName(rcode) }
        };

        if (string.IsNullOrWhiteSpace(version)) return id;

        version = BannerParser.Sanitize(version);
        id.Extra["dns.version"] = version;
        var (product, ver) = ParseVersion(version);
        // A forwarding resolver (typical for home routers) may pass CHAOS queries upstream, so the disclosed
        // version can belong to another server. The protocol is certain; the product/version is only probable.
        id.Extra["dns.versionNote"] = "upstream-possible";
        return product is null ? id : id with
        {
            Product = product, Vendor = ProductCatalog.Find(product)?.CpeVendor, Version = ver,
            Cpe = ProductCatalog.Cpe(product, ver), Confidence = 55,
            DistributionHint = BannerParser.DistributionFrom(version)
        };
    }

    public static (string? Product, string? Version) ParseVersion(string text)
    {
        if (Dnsmasq().Match(text) is { Success: true } d) return ("dnsmasq", d.Groups[1].Value);
        if (Unbound().Match(text) is { Success: true } u) return ("Unbound", u.Groups[1].Value);
        if (PowerDns().Match(text) is { Success: true } p) return ("PowerDNS Recursor", p.Groups[1].Value);
        if (Bind().Match(text) is { Success: true } b) return ("BIND", b.Groups[1].Value);
        return (null, null);
    }

    private static string? TryReadFirstTxt(ReadOnlySpan<byte> msg, int questions)
    {
        var offset = 12;
        for (var q = 0; q < questions; q++)
        {
            if (!SkipName(msg, ref offset) || offset + 4 > msg.Length) return null;
            offset += 4;
        }

        if (!SkipName(msg, ref offset) || offset + 10 > msg.Length) return null;
        var type = BinaryPrimitives.ReadUInt16BigEndian(msg[offset..]);
        var rdLength = BinaryPrimitives.ReadUInt16BigEndian(msg[(offset + 8)..]);
        offset += 10;
        if (type != 16 || rdLength < 1 || offset + rdLength > msg.Length) return null;
        var length = msg[offset];
        return length == 0 || length >= rdLength ? null : Encoding.ASCII.GetString(msg.Slice(offset + 1, length));
    }

    private static bool SkipName(ReadOnlySpan<byte> msg, ref int offset)
    {
        for (var guard = 0; guard < 128 && offset < msg.Length; guard++)
        {
            var len = msg[offset];
            if (len == 0) { offset++; return true; }
            if ((len & 0xC0) == 0xC0) { offset += 2; return offset <= msg.Length; }
            offset += len + 1;
        }

        return false;
    }

    private static string RcodeName(int rcode) => rcode switch
    {
        0 => "NOERROR", 1 => "FORMERR", 2 => "SERVFAIL", 3 => "NXDOMAIN", 4 => "NOTIMP", 5 => "REFUSED", _ => rcode.ToString()
    };

    [GeneratedRegex(@"dnsmasq-(\d+(?:\.\d+)+)", RegexOptions.IgnoreCase)] private static partial Regex Dnsmasq();
    [GeneratedRegex(@"unbound (\d+(?:\.\d+)+)", RegexOptions.IgnoreCase)] private static partial Regex Unbound();
    [GeneratedRegex(@"PowerDNS Recursor (\d+(?:\.\d+)+)", RegexOptions.IgnoreCase)] private static partial Regex PowerDns();
    [GeneratedRegex(@"^(\d+\.\d+\.\d+)(?:[-.\s]|$)")] private static partial Regex Bind();
}
