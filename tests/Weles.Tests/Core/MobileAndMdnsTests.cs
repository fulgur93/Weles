using System.Buffers.Binary;
using System.Net;
using System.Text;
using Weles.Core.Enums;
using Weles.Core.Models;
using Weles.Core.Networking;
using Weles.Core.Rules;

namespace Weles.Tests.Core;

/// <summary>Builds DNS responses for tests (names written uncompressed unless a pointer is requested).</summary>
public static class DnsTestPackets
{
    public static byte[] Name(string name) =>
        [.. name.Split('.').SelectMany(l => (byte[])[(byte)l.Length, .. Encoding.ASCII.GetBytes(l)]), 0];

    public static byte[] Record(string name, ushort type, byte[] rdata) =>
        [.. Name(name), (byte)(type >> 8), (byte)type, 0x80, 0x01, 0, 0, 0, 120, (byte)(rdata.Length >> 8), (byte)rdata.Length, .. rdata];

    public static byte[] Ptr(string name, string target) => Record(name, DnsMessage.TypePtr, Name(target));

    public static byte[] Srv(string name, ushort port, string target) =>
        Record(name, DnsMessage.TypeSrv, [0, 0, 0, 0, (byte)(port >> 8), (byte)port, .. Name(target)]);

    public static byte[] Txt(string name, params string[] texts) =>
        Record(name, DnsMessage.TypeTxt, [.. texts.SelectMany(t => (byte[])[(byte)t.Length, .. Encoding.ASCII.GetBytes(t)])]);

    public static byte[] A(string name, string ip) => Record(name, DnsMessage.TypeA, IPAddress.Parse(ip).GetAddressBytes());

    public static byte[] Response(ushort id, params byte[][] answers)
    {
        var header = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header, id);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), 0x8400);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6), (ushort)answers.Length);
        return [.. header, .. answers.SelectMany(a => a)];
    }
}

public class MobileProfileTests
{
    [Fact]
    public void Mobile_profile_extends_quick_with_phone_services()
    {
        Assert.True(PortSpecification.TryParse("mobile", out var ports, out _));
        foreach (var p in new[] { 22, 80, 443, 5555, 2121, 8022, 8888, 1714, 1716, 1764, 62078 }) Assert.Contains(p, ports);
        Assert.Equal(ports.Count, ports.Distinct().Count());
        Assert.Equal("adb", WellKnownPorts.NameOf(5555));
    }
}

public class AdbHandshakeTests
{
    [Fact]
    public void Connect_packet_has_valid_header()
    {
        var p = AdbHandshake.BuildConnect();
        Assert.Equal("CNXN", Encoding.ASCII.GetString(p, 0, 4));
        Assert.Equal(BinaryPrimitives.ReadUInt32LittleEndian(p) ^ 0xFFFFFFFF, BinaryPrimitives.ReadUInt32LittleEndian(p.AsSpan(20)));
        Assert.Equal((uint)(p.Length - 24), BinaryPrimitives.ReadUInt32LittleEndian(p.AsSpan(12)));
        Assert.Equal("host::\0", Encoding.ASCII.GetString(p, 24, p.Length - 24));
    }

    public static byte[] Message(string command, string payload)
    {
        var data = Encoding.ASCII.GetBytes(payload);
        var header = new byte[24];
        var cmd = BinaryPrimitives.ReadUInt32LittleEndian(Encoding.ASCII.GetBytes(command));
        BinaryPrimitives.WriteUInt32LittleEndian(header, cmd);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(12), (uint)data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(20), cmd ^ 0xFFFFFFFF);
        return [.. header, .. data];
    }

    [Fact]
    public void Auth_challenge_means_adb_enabled_with_authorization()
    {
        var id = AdbHandshake.Parse(Message("AUTH", new string('x', 20)))!;
        Assert.Equal(("adb", "required", "Android"), (id.ServiceName, id.Extra["adb.auth"], id.OsHint));
    }

    [Fact]
    public void Connect_reply_means_no_authorization_and_reveals_model()
    {
        var id = AdbHandshake.Parse(Message("CNXN", "device::ro.product.name=lisa;ro.product.model=2109119DG;ro.product.device=lisa;features=shell_v2"))!;
        Assert.Equal("none", id.Extra["adb.auth"]);
        Assert.Equal("2109119DG", id.Extra["adb.model"]);
        Assert.Equal("lisa", id.Extra["adb.device"]);
    }

    [Fact]
    public void Garbage_is_not_adb()
    {
        Assert.Null(AdbHandshake.Parse("HTTP/1.1 400 Bad Request\r\n\r\n                    "u8.ToArray()));
        Assert.Null(AdbHandshake.Parse([1, 2, 3]));
    }
}

public class DnsMessageTests
{
    [Fact]
    public void Parses_ptr_srv_txt_and_a_records()
    {
        var msg = DnsTestPackets.Response(0,
            DnsTestPackets.Ptr("_adb-tls-connect._tcp.local", "adb-1a2b._adb-tls-connect._tcp.local"),
            DnsTestPackets.Srv("adb-1a2b._adb-tls-connect._tcp.local", 37451, "Android.local"),
            DnsTestPackets.Txt("adb-1a2b._adb-tls-connect._tcp.local", "v=ADB_SECURE_SERVICE_VERSION"),
            DnsTestPackets.A("Android.local", "192.168.0.170"));

        Assert.True(DnsMessage.TryParse(msg, out _, out var r));
        Assert.Equal("adb-1a2b._adb-tls-connect._tcp.local", r[0].Target);
        Assert.Equal((ushort)37451, r[1].Port);
        Assert.Equal("Android.local", r[1].Target);
        Assert.Equal("v=ADB_SECURE_SERVICE_VERSION", r[2].Texts!.Single());
        Assert.Equal(IPAddress.Parse("192.168.0.170"), r[3].Address);
    }

    [Fact]
    public void Compressed_names_are_followed()
    {
        // second record's name is a pointer to offset 12 (the first record's name)
        var first = DnsTestPackets.A("host.local", "10.0.0.1");
        byte[] second = [0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 10, 0, 0, 2];
        Assert.True(DnsMessage.TryParse(DnsTestPackets.Response(1, first, second), out _, out var r));
        Assert.Equal("host.local", r[1].Name);
    }

    [Fact]
    public void Pointer_loop_and_truncation_do_not_throw()
    {
        byte[] loop = [0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 1, 2, 3, 4];
        Assert.False(DnsMessage.TryParse(DnsTestPackets.Response(1, loop), out _, out _));

        var valid = DnsTestPackets.Response(1, DnsTestPackets.A("a.local", "10.0.0.1"), DnsTestPackets.A("b.local", "10.0.0.2"));
        Assert.True(DnsMessage.TryParse(valid[..^3], out _, out var partial));
        Assert.Single(partial);
        Assert.False(DnsMessage.TryParse([1, 2, 3], out _, out _));
    }

    [Fact]
    public void Query_contains_requested_names()
    {
        var q = DnsMessage.BuildQuery(5, [("_services._dns-sd._udp.local", DnsMessage.TypePtr)]);
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(4)));
        Assert.Contains("_dns-sd", Encoding.ASCII.GetString(q));
    }
}

public class MobileClassificationTests
{
    private static HostClassification Classify(int[] ports, string[] mdns, params ServiceIdentification[] services) =>
        AssetClassifier.Classify(new HostEvidence(ports, services, null, null, false, null, HasRandomizedMac: true, MdnsServiceTypes: mdns));

    [Fact]
    public void Android_wireless_debugging_announcement_makes_a_mobile_device()
    {
        var c = Classify([], ["_adb-tls-connect._tcp"]);
        Assert.Equal((AssetType.MobileDevice, "Android"), (c.Type, c.OsFamily));
        Assert.Contains(c.Reasons, r => r.Contains("mDNS"));
    }

    [Fact]
    public void Adb_service_reveals_android_and_model()
    {
        var adb = new ServiceIdentification { ServiceName = "adb", Method = "adb-handshake", OsHint = "Android" };
        adb.Extra["adb.model"] = "2109119DG";
        var c = Classify([5555], [], adb);
        Assert.Equal(AssetType.MobileDevice, c.Type);
        Assert.Contains(c.Reasons, r => r.Contains("2109119DG"));
    }

    [Fact]
    public void Iphone_sync_port_makes_an_ios_device()
    {
        var c = Classify([62078], []);
        Assert.Equal((AssetType.MobileDevice, "iOS/iPadOS"), (c.Type, c.OsFamily));
    }

    [Fact]
    public void Google_cast_announcement_is_iot_not_mobile()
    {
        Assert.Equal(AssetType.IoTDevice, Classify([8008, 8009], ["_googlecast._tcp"]).Type);
    }

    [Fact]
    public void Printer_announcement_is_a_printer()
    {
        Assert.Equal(AssetType.Printer, Classify([631], ["_ipp._tcp"]).Type);
    }
}
