using System.IO.Compression;
using System.Net;
using System.Text;
using Weles.Infrastructure.Discovery;

namespace Weles.Tests.Scanning;

public class OuiAndArpTests
{
    private static readonly OuiDatabase Bundled = new();

    [Fact]
    public void Bundled_registry_is_loaded_and_resolves_known_vendors()
    {
        Assert.True(Bundled.Count > 20_000); // IEEE MA-L registry: ~26.5k assignments
        Assert.Contains("Cisco", Bundled.Lookup("00:00:0C:12:34:56"));
    }

    [Theory]
    [InlineData("08-00-27-aa-bb-cc", "Oracle VirtualBox")]
    [InlineData("5254.00ab.cdef", "QEMU/KVM (virtio)")]
    public void Virtualization_prefixes_and_formats(string mac, string vendor)
    {
        Assert.Equal(vendor, Bundled.Lookup(mac));
    }

    [Fact]
    public void Randomized_mac_is_reported_as_locally_administered()
    {
        Assert.StartsWith("Adres losowy", Bundled.Lookup("da:a1:19:00:00:01"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("00:00:00:00:00:00")]
    [InlineData("ff:ff:ff:ff:ff:ff")]
    [InlineData("zz:11")]
    public void Invalid_macs_yield_no_vendor(string? mac)
    {
        Assert.Null(Bundled.Lookup(mac));
    }

    [Fact]
    public void Csv_parser_handles_quoted_commas()
    {
        var csv = "Registry,Assignment,Organization Name,Organization Address\nMA-L,ABCDEF,\"Acme, Inc.\",\"Street 1, City\"\nMA-M,ABCDEF1,Other,x\n";
        var gz = new MemoryStream();
        using (var z = new GZipStream(gz, CompressionLevel.Fastest, leaveOpen: true)) z.Write(Encoding.UTF8.GetBytes(csv));
        var db = new OuiDatabase(() => new MemoryStream(gz.ToArray()));

        Assert.Equal(1, db.Count);
        Assert.Equal("Acme, Inc.", db.Lookup("ab:cd:ef:00:00:01"));
    }

    [Fact]
    public void Linux_arp_table_keeps_only_complete_entries()
    {
        const string content = """
            IP address       HW type     Flags       HW address            Mask     Device
            192.168.0.1      0x1         0x2         68:7F:F0:72:00:14     *        wlp68s0
            192.168.0.50     0x1         0x0         00:00:00:00:00:00     *        wlp68s0
            192.168.0.38     0x1         0x6         e8:65:d4:59:42:c0     *        wlp68s0
            """;

        var table = ArpTable.ParseLinux(content);

        Assert.Equal(2, table.Count);
        Assert.Equal("68:7f:f0:72:00:14", table[IPAddress.Parse("192.168.0.1")]);
        Assert.False(table.ContainsKey(IPAddress.Parse("192.168.0.50")));
    }
}
