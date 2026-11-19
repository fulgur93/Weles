using Weles.Core.Enums;
using Weles.Infrastructure.Queries;

namespace Weles.Tests.Assets;

public class AssetListEngineTests
{
    private static AssetListItem Item(int id, string name, string ip, AssetType type = AssetType.Unknown, AssetStatus status = AssetStatus.Active,
        int[]? ports = null, string? os = null, string? vendor = null, string[]? products = null, int? segment = 1, double? risk = null) =>
        new(id, name, false, null, ip, null, vendor, type, false, os, AssetCriticality.Medium, segment, segment is null ? null : $"10.0.{segment}.0/24",
            segment is null ? null : $"10.0.{segment}.0/24 · router aa:00:00:00:00:0{segment}",
            (ports ?? []).Length, ports ?? [], products ?? [], 0, risk, null, status, DateTime.UtcNow.AddDays(-id), DateTime.UtcNow, 1);

    private static readonly List<AssetListItem> Inventory =
    [
        Item(1, "Serwer Łódź", "10.0.1.10", AssetType.Server, ports: [22, 443], os: "Linux", products: ["OpenSSH 8.9p1", "nginx 1.18.0"]),
        Item(2, "Drukarka", "10.0.1.2", AssetType.Printer, AssetStatus.Missing, ports: [9100]),
        Item(3, "Telefon Xiaomi", "10.0.1.170", AssetType.MobileDevice, AssetStatus.New, os: "Android"),
        Item(4, "Router", "10.0.1.1", AssetType.Router, ports: [53, 80, 443], vendor: "TP-Link Systems Inc", risk: 40),
        Item(5, "Kamera", "10.0.2.20", AssetType.IpCamera, ports: [554], segment: 2, risk: 80),
    ];

    private static AssetListPage Run(AssetListQuery q) => AssetListEngine.Apply(Inventory, q);

    [Theory]
    [InlineData("łódź", 1)]          // Polish, case-insensitive
    [InlineData("LODZ", 1)]          // diacritics-insensitive, including ł → l
    [InlineData("lódz", 1)]
    [InlineData("openssh", 1)]       // product of the latest observation
    [InlineData("9100", 2)]          // open port number
    [InlineData("tp-link", 4)]       // vendor
    [InlineData("10.0.2.", 5)]       // IP prefix
    public void Search_matches_names_products_ports_vendors_and_addresses(string search, int expectedId)
    {
        Assert.Equal([expectedId], Run(new AssetListQuery { Search = search }).Items.Select(i => i.Id));
    }

    [Fact]
    public void Search_terms_are_combined_with_and()
    {
        Assert.Equal([1], Run(new AssetListQuery { Search = "linux 443" }).Items.Select(i => i.Id));
    }

    [Fact]
    public void Filters_and_facet_counts()
    {
        var page = Run(new AssetListQuery { Statuses = new HashSet<AssetStatus> { AssetStatus.Active }, SegmentIds = new HashSet<int> { 1 } });
        Assert.Equal([4, 1, 3], page.Items.Select(i => i.Id)); // default IP order: .1, .10, .170; the new phone is active too
        Assert.Equal(1, page.StatusCounts[AssetStatus.Missing]); // facet ignores its own filter
        Assert.Equal(2, page.Segments.Count);

        Assert.Equal([3], Run(new AssetListQuery { OsFamily = "android" }).Items.Select(i => i.Id));
        Assert.DoesNotContain(3, Run(new AssetListQuery { OnlyWithOpenPorts = true }).Items.Select(i => i.Id));
        Assert.Equal([5], Run(new AssetListQuery { Types = new HashSet<AssetType> { AssetType.IpCamera } }).Items.Select(i => i.Id));
    }

    [Fact]
    public void Multi_column_sort_applies_levels_in_order()
    {
        var page = Run(new AssetListQuery { Sort = [new(AssetSortColumn.OpenPorts, true), new(AssetSortColumn.Name, false)] });
        Assert.Equal([4, 1, 2, 5, 3], page.Items.Select(i => i.Id)); // 3 ports, 2 ports, then 1-port items by name: Drukarka, Kamera
    }

    [Fact]
    public void Ip_sort_is_numeric_and_missing_risk_sorts_last()
    {
        Assert.Equal([4, 2, 1, 3, 5], Run(new AssetListQuery()).Items.Select(i => i.Id));
        Assert.Equal([5, 4], Run(new AssetListQuery { Sort = [new(AssetSortColumn.Risk, true)] }).Items.Take(2).Select(i => i.Id));
    }

    [Fact]
    public void Paging_is_clamped()
    {
        var page = Run(new AssetListQuery { PageSize = 2, Page = 99 });
        Assert.Equal(3, page.Page);
        Assert.Equal(3, page.PageCount);
        Assert.Single(page.Items);
        Assert.Equal(5, page.TotalCount);
    }

    [Fact]
    public void Devices_found_in_their_first_scan_are_listed_as_active()
    {
        // Reported on a real network: after the first scan every device was "New" and the "Active" tab was empty.
        var page = Run(new AssetListQuery { Statuses = new HashSet<AssetStatus> { AssetStatus.Active } });
        Assert.Contains(3, page.Items.Select(i => i.Id));
        Assert.Equal(4, page.StatusCounts[AssetStatus.Active]);
        Assert.Equal(1, page.StatusCounts[AssetStatus.New]);
        Assert.Equal(5, page.AllStatusesCount); // "Wszystkie" does not double-count new devices

        Assert.Equal([3], Run(new AssetListQuery { Statuses = new HashSet<AssetStatus> { AssetStatus.New } }).Items.Select(i => i.Id));
    }

    [Fact]
    public void Network_filter_shows_only_the_selected_networks()
    {
        Assert.Equal([5], Run(new AssetListQuery { SegmentIds = new HashSet<int> { 2 } }).Items.Select(i => i.Id));
        Assert.Empty(Run(new AssetListQuery { SegmentIds = new HashSet<int>() }).Items);
        Assert.Equal(5, Run(new AssetListQuery { SegmentIds = null }).TotalCount);
        Assert.Equal([5], Run(new AssetListQuery { Search = "aa:00:00:00:00:02" }).Items.Select(i => i.Id)); // network label is searchable

        // Current-network view: other networks hidden, assets without a segment (loopback, routed) stay.
        var current = Run(new AssetListQuery { ExcludedSegmentIds = new HashSet<int> { 1 } });
        Assert.Equal([5], current.Items.Select(i => i.Id));
        Assert.Equal(4, current.HiddenOtherNetworks);
    }
}
