using System.Buffers.Binary;
using System.Text;
using Weles.Core.Rules;

namespace Weles.Tests.Core;

public class DnsVersionProbeTests
{
    /// <summary>Builds a TCP-framed DNS response echoing the query, optionally with one TXT answer.</summary>
    public static byte[] Response(byte[] query, int rcode, string? txt)
    {
        var msg = query.Skip(2).ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(2), (ushort)(0x8000 | 0x0400 | rcode));
        var body = new List<byte>(msg);
        if (txt is not null)
        {
            BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(6), 1);
            body = [.. msg];
            var data = Encoding.ASCII.GetBytes(txt);
            body.AddRange([0xC0, 0x0C, 0x00, 0x10, 0x00, 0x03, 0, 0, 0, 0, 0, (byte)(data.Length + 1), (byte)data.Length]);
            body.AddRange(data);
        }

        var framed = new byte[body.Count + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)body.Count);
        body.CopyTo(framed, 2);
        return framed;
    }

    [Fact]
    public void Query_is_a_tcp_framed_chaos_txt_question_for_version_bind()
    {
        var q = DnsVersionProbe.BuildQuery(0x1234);
        Assert.Equal(q.Length - 2, BinaryPrimitives.ReadUInt16BigEndian(q));
        Assert.Equal(0x1234, BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(2)));
        Assert.Contains("version", Encoding.ASCII.GetString(q));
        Assert.Equal([0x00, 0x10, 0x00, 0x03], q[^4..]);
    }

    [Theory]
    [InlineData("dnsmasq-2.80", "dnsmasq", "2.80")]
    [InlineData("unbound 1.17.1", "Unbound", "1.17.1")]
    [InlineData("9.18.18-0ubuntu0.22.04.1-Ubuntu", "BIND", "9.18.18")]
    public void Disclosed_version_is_identified(string txt, string product, string version)
    {
        var q = DnsVersionProbe.BuildQuery(7);
        var id = DnsVersionProbe.Parse(Response(q, 0, txt), 7)!;

        Assert.Equal(("dns", product, version), (id.ServiceName, id.Product, id.Version));
        Assert.Equal(txt, id.Extra["dns.version"]);
        // Regression from a real scan: a home router reported its ISP's BIND – the version may come from upstream.
        Assert.True(id.Confidence < 60);
        Assert.Equal("upstream-possible", id.Extra["dns.versionNote"]);
    }

    [Fact]
    public void Refused_query_still_confirms_dns_without_inventing_a_version()
    {
        var q = DnsVersionProbe.BuildQuery(9);
        var id = DnsVersionProbe.Parse(Response(q, 5, null), 9)!;

        Assert.Equal("dns", id.ServiceName);
        Assert.Equal("REFUSED", id.Extra["dns.rcode"]);
        Assert.Null(id.Product);
        Assert.Null(id.Version);
    }

    [Fact]
    public void Unknown_version_string_is_kept_raw()
    {
        var q = DnsVersionProbe.BuildQuery(3);
        var id = DnsVersionProbe.Parse(Response(q, 0, "none of your business"), 3)!;
        Assert.Null(id.Product);
        Assert.Equal("none of your business", id.Extra["dns.version"]);
    }

    [Fact]
    public void Wrong_id_truncated_or_non_response_data_is_rejected()
    {
        var q = DnsVersionProbe.BuildQuery(1);
        Assert.Null(DnsVersionProbe.Parse(Response(q, 0, null), 2));
        Assert.Null(DnsVersionProbe.Parse(q, 1));                   // a query, not a response
        Assert.Null(DnsVersionProbe.Parse([0, 40, 1, 2, 3], 1));
        Assert.Null(DnsVersionProbe.Parse("HTTP/1.1 400 Bad Request"u8.ToArray(), 1));
    }

    [Fact]
    public void Malformed_answer_section_does_not_throw()
    {
        var q = DnsVersionProbe.BuildQuery(5);
        var r = Response(q, 0, "dnsmasq-2.80");
        var truncated = r[..^6];
        BinaryPrimitives.WriteUInt16BigEndian(truncated, (ushort)(truncated.Length - 2));
        var id = DnsVersionProbe.Parse(truncated, 5)!;
        Assert.Equal("dns", id.ServiceName);
        Assert.Null(id.Version);
    }
}
