using System.Net;
using System.Net.Sockets;
using Weles.Core.Networking;

namespace Weles.Tests.Core;

public class ScopeResolverTests
{
    private static Task<IReadOnlyList<IPAddress>> NoDns(string d, CancellationToken c) => Task.FromResult<IReadOnlyList<IPAddress>>([]);

    private static Task<ScopeResolution> Resolve(bool allowPublic, int max, params (string, bool)[] entries) =>
        ScopeResolver.ResolveAsync(entries.Select(e => new ScopeEntry(e.Item1, e.Item2)), allowPublic, max, NoDns);

    [Fact]
    public async Task Exclusions_win_over_inclusions()
    {
        var r = await Resolve(false, 4096, ("192.168.1.0/24", false), ("192.168.1.1", true), ("192.168.1.100-254", true));

        Assert.True(r.IsValid);
        Assert.Equal(98, r.Addresses.Count); // .2 – .99
        Assert.DoesNotContain(IPAddress.Parse("192.168.1.1"), r.Addresses);
        Assert.DoesNotContain(IPAddress.Parse("192.168.1.150"), r.Addresses);
    }

    [Fact]
    public async Task Excluding_a_cidr_removes_its_network_and_broadcast_too()
    {
        var r = await Resolve(false, 4096, ("10.0.0.0-10.0.0.20", false), ("10.0.0.0/29", true));
        Assert.Equal(IPAddress.Parse("10.0.0.8"), r.Addresses.First());
    }

    [Fact]
    public async Task Overlapping_entries_are_deduplicated()
    {
        var r = await Resolve(false, 4096, ("10.0.0.0/30", false), ("10.0.0.1", false), ("10.0.0.1-2", false));
        Assert.Equal(2, r.Addresses.Count);
    }

    [Fact]
    public async Task Public_addresses_are_skipped_without_permission()
    {
        var r = await Resolve(false, 4096, ("8.8.8.8", false), ("10.0.0.1", false));

        Assert.Equal([IPAddress.Parse("10.0.0.1")], r.Addresses);
        Assert.Equal(1, r.SkippedPublic);
        Assert.Contains(r.Warnings, w => w.Contains("publicznych"));
    }

    [Fact]
    public async Task Public_addresses_are_kept_with_permission()
    {
        var r = await Resolve(true, 4096, ("8.8.8.8", false));
        Assert.Single(r.Addresses);
    }

    [Fact]
    public async Task Only_public_addresses_without_permission_is_an_error()
    {
        var r = await Resolve(false, 4096, ("1.1.1.1", false));
        Assert.False(r.IsValid);
    }

    [Fact]
    public async Task Reserved_addresses_are_never_scanned()
    {
        var r = await Resolve(true, 4096, ("224.0.0.1", false), ("10.0.0.1", false));
        Assert.Equal([IPAddress.Parse("10.0.0.1")], r.Addresses);
    }

    [Fact]
    public async Task Exceeding_host_limit_is_rejected()
    {
        var r = await Resolve(false, 100, ("10.0.0.0/24", false));
        Assert.False(r.IsValid);
        Assert.Contains("254", r.Errors.Single());
    }

    [Fact]
    public async Task Invalid_entry_makes_scope_invalid()
    {
        var r = await Resolve(false, 100, ("10.0.0.0/8", false));
        Assert.False(r.IsValid);
    }

    [Fact]
    public async Task Domains_are_resolved_and_subject_to_the_same_rules()
    {
        Task<IReadOnlyList<IPAddress>> Dns(string d, CancellationToken c) =>
            Task.FromResult<IReadOnlyList<IPAddress>>(d == "nas.local"
                ? [IPAddress.Parse("192.168.5.5"), IPAddress.Parse("fd00::5")]
                : [IPAddress.Parse("93.184.216.34")]);

        var r = await ScopeResolver.ResolveAsync([new("nas.local", false), new("example.com", false)], false, 100, Dns);

        Assert.Contains(IPAddress.Parse("192.168.5.5"), r.Addresses);
        Assert.Contains(r.Addresses, a => a.AddressFamily == AddressFamily.InterNetworkV6);
        Assert.DoesNotContain(IPAddress.Parse("93.184.216.34"), r.Addresses);
    }

    [Fact]
    public async Task Dns_failure_is_a_warning_not_a_crash()
    {
        Task<IReadOnlyList<IPAddress>> Dns(string d, CancellationToken c) => throw new SocketException((int)SocketError.HostNotFound);

        var r = await ScopeResolver.ResolveAsync([new("missing.local", false), new("10.0.0.1", false)], false, 100, Dns);

        Assert.True(r.IsValid);
        Assert.Contains(r.Warnings, w => w.Contains("missing.local"));
    }
}

public class PortSpecificationTests
{
    [Fact]
    public void Profiles_contain_the_required_ports()
    {
        Assert.True(PortSpecification.TryParse("quick", out var ports, out _));
        foreach (var p in new[] { 20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017 })
        {
            Assert.Contains(p, ports);
        }

        Assert.True(PortSpecification.TryParse("standard", out var standard, out _));
        Assert.True(standard.Count > ports.Count);
        Assert.Equal(standard.Count, standard.Distinct().Count());
    }

    [Fact]
    public void Custom_list_and_ranges_are_parsed_sorted_and_deduplicated()
    {
        Assert.True(PortSpecification.TryParse("8080, 22,8000-8002 22", out var ports, out _));
        Assert.Equal([22, 8000, 8001, 8002, 8080], ports);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("100-50")]
    [InlineData("http")]
    public void Invalid_specifications_are_rejected(string spec)
    {
        Assert.False(PortSpecification.TryParse(spec, out _, out var error));
        Assert.NotNull(error);
    }
}
