using Weles.Core.Enums;
using Weles.Core.Networking;

namespace Weles.Tests.Core;

public class TargetParserTests
{
    [Theory]
    [InlineData("192.168.1.10", ScanTargetEntryKind.IpAddress, "192.168.1.10", 1)]
    [InlineData(" 10.0.0.0/24 ", ScanTargetEntryKind.Cidr, "10.0.0.0/24", 254)]
    [InlineData("10.0.0.77/24", ScanTargetEntryKind.Cidr, "10.0.0.0/24", 254)]
    [InlineData("10.0.0.5/32", ScanTargetEntryKind.Cidr, "10.0.0.5/32", 1)]
    [InlineData("10.0.0.4/31", ScanTargetEntryKind.Cidr, "10.0.0.4/31", 2)]
    [InlineData("192.168.1.10-20", ScanTargetEntryKind.IpRange, "192.168.1.10-192.168.1.20", 11)]
    [InlineData("10.0.0.250-10.0.1.5", ScanTargetEntryKind.IpRange, "10.0.0.250-10.0.1.5", 12)]
    public void Parses_ipv4_forms(string raw, ScanTargetEntryKind kind, string normalized, long count)
    {
        Assert.True(TargetParser.TryParse(raw, out var t, out var error), error);
        Assert.Equal(kind, t.Kind);
        Assert.Equal(normalized, t.Normalized);
        Assert.Equal(count, t.Ipv4Range!.Value.Count);
    }

    [Theory]
    [InlineData("NAS.Firma.Local.", "nas.firma.local")]
    [InlineData("example.com", "example.com")]
    [InlineData("router", "router")]
    public void Parses_domains(string raw, string normalized)
    {
        Assert.True(TargetParser.TryParse(raw, out var t, out _));
        Assert.Equal(ScanTargetEntryKind.Domain, t.Kind);
        Assert.Equal(normalized, t.Domain);
    }

    [Fact]
    public void Parses_single_ipv6()
    {
        Assert.True(TargetParser.TryParse("fd00::10", out var t, out _));
        Assert.NotNull(t.Ipv6Address);
    }

    [Theory]
    [InlineData("")]
    [InlineData("256.1.1.1")]
    [InlineData("1")]                  // IPAddress.TryParse would accept this as 0.0.0.1
    [InlineData("10.0.0.0/8")]         // larger than /16
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.20-10")]       // end before start
    [InlineData("10.0.0.0-10.2.0.0")]  // more than 65536 addresses
    [InlineData("fd00::/64")]
    [InlineData("-bad-.com")]
    [InlineData("ex ample.com")]
    public void Rejects_invalid_or_too_large_entries(string raw)
    {
        Assert.False(TargetParser.TryParse(raw, out _, out var error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void Splits_free_form_lists_and_ignores_comments()
    {
        Assert.Equal(["10.0.0.1", "10.0.0.2", "nas.local", "10.0.1.0/24"],
            TargetParser.SplitEntries("10.0.0.1, 10.0.0.2\n#comment\r\nnas.local;10.0.1.0/24"));
    }

    [Theory]
    [InlineData("10.1.2.3", AddressScope.Private)]
    [InlineData("172.31.255.1", AddressScope.Private)]
    [InlineData("172.32.0.1", AddressScope.Public)]
    [InlineData("192.168.0.1", AddressScope.Private)]
    [InlineData("127.0.0.1", AddressScope.Loopback)]
    [InlineData("169.254.10.1", AddressScope.LinkLocal)]
    [InlineData("100.64.1.1", AddressScope.SharedAddressSpace)]
    [InlineData("8.8.8.8", AddressScope.Public)]
    [InlineData("224.0.0.251", AddressScope.Reserved)]
    [InlineData("0.0.0.0", AddressScope.Reserved)]
    [InlineData("fd12::1", AddressScope.Private)]
    [InlineData("fe80::1", AddressScope.LinkLocal)]
    [InlineData("2001:4860:4860::8888", AddressScope.Public)]
    public void Classifies_address_scope(string ip, AddressScope expected)
    {
        Assert.Equal(expected, AddressClassifier.Classify(System.Net.IPAddress.Parse(ip)));
    }
}
