using System.Text.Json;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Rules;

namespace Weles.Tests.Assets;

public class AssetRulesTests
{
    private static string Snapshot(params (string Value, bool IsExclusion)[] entries) =>
        JsonSerializer.Serialize(entries.Select(e => new { e.Value, e.IsExclusion }));

    [Fact]
    public void Auto_name_prefers_hostname_then_vendor_then_ip()
    {
        Assert.Equal("nas.local", AssetNaming.AutoName("nas.local", "Synology", "10.0.0.5"));
        Assert.Equal("Synology (10.0.0.5)", AssetNaming.AutoName(null, "Synology", "10.0.0.5"));
        Assert.Equal("10.0.0.5", AssetNaming.AutoName(null, AssetNaming.RandomMacVendor, "10.0.0.5"));
        Assert.Equal("Telefon Xiaomi", AssetNaming.DisplayName(" Telefon Xiaomi ", "android.local", null, "10.0.0.5"));
        Assert.Equal("android.local", AssetNaming.DisplayName("  ", "android.local", null, "10.0.0.5"));
    }

    [Fact]
    public void Coverage_is_rebuilt_from_snapshot_with_exclusions()
    {
        var c = ScopeCoverage.FromSnapshot(Snapshot(("192.168.0.0/24", false), ("192.168.0.128/25", true), ("fd00::1", false)));
        Assert.True(c.Covers("192.168.0.10"));
        Assert.False(c.Covers("192.168.0.200"));
        Assert.False(c.Covers("10.0.0.1"));
        Assert.True(c.Covers("fd00::1"));
        Assert.False(ScopeCoverage.FromSnapshot("not json").Covers("192.168.0.10"));
        Assert.False(ScopeCoverage.FromSnapshot(null).Covers("192.168.0.10"));
    }

    private static readonly List<CompletedScanCoverage> Scans =
    [
        new(3, new DateTime(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc), ScopeCoverage.FromSnapshot(Snapshot(("10.0.1.0/24", false)))),
        new(2, new DateTime(2026, 11, 2, 0, 0, 0, DateTimeKind.Utc), ScopeCoverage.FromSnapshot(Snapshot(("10.0.0.0/24", false)))),
        new(1, new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc), ScopeCoverage.FromSnapshot(Snapshot(("10.0.0.0/24", false)))),
    ];

    [Theory]
    [InlineData("10.0.0.5", new[] { 1, 2 }, 1, AssetStatus.Active, 2)]
    [InlineData("10.0.0.6", new[] { 1 }, 1, AssetStatus.Intermittent, 2)]  // scan 2 covered it and did not find it – once is not "missing" yet
    [InlineData("10.0.0.7", new[] { 2 }, 2, AssetStatus.New, 2)]
    [InlineData("10.0.1.9", new[] { 3 }, 3, AssetStatus.New, 3)]
    [InlineData("172.16.0.1", new int[0], null, AssetStatus.NotCovered, null)]
    [InlineData("example-domain-host", new[] { 1 }, 1, AssetStatus.New, 1)] // observed via domain – observation establishes coverage
    public void Presence_is_judged_against_the_latest_covering_scan(string ip, int[] observed, int? first, AssetStatus expected, int? referenceScan)
    {
        var presence = AssetStatusRules.Evaluate(ip, Scans, observed.ToHashSet(), first);
        Assert.Equal(expected, presence.Status);
        Assert.Equal(referenceScan, presence.ReferenceScanId);
    }

    [Fact]
    public void A_host_becomes_missing_only_after_several_silent_scans_in_a_row()
    {
        var day = new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc);
        var covering = Enumerable.Range(1, 5).Reverse()
            .Select(i => new CompletedScanCoverage(i, day.AddDays(i), ScopeCoverage.FromSnapshot(Snapshot(("10.0.0.0/24", false))))).ToList();
        AssetPresence Seen(params int[] scans) => AssetStatusRules.Evaluate("10.0.0.6", covering, scans.ToHashSet(), 1);

        Assert.Equal((AssetStatus.Intermittent, 1), (Seen(1, 2, 3, 4).Status, Seen(1, 2, 3, 4).ConsecutiveMisses));
        Assert.Equal((AssetStatus.Intermittent, 2), (Seen(1, 2, 3).Status, Seen(1, 2, 3).ConsecutiveMisses));
        Assert.Equal((AssetStatus.Missing, 3), (Seen(1, 2).Status, Seen(1, 2).ConsecutiveMisses));
        Assert.Equal(5, Seen(1, 2).ReferenceScanId);                         // judged against the latest covering scan
        Assert.Equal(AssetStatus.Active, Seen(1, 3, 5).Status);             // answered in the latest scan
        Assert.Equal(AssetStatus.Missing, AssetStatusRules.Evaluate("10.0.0.6", covering, new HashSet<int> { 1, 2, 3, 4 }, 1, inactiveAfterMisses: 1).Status);
    }

    [Fact]
    public void Presence_history_finds_unstable_hosts_and_time_of_day_patterns()
    {
        var monday = new DateTime(2026, 11, 2);
        // A workstation: answers in the afternoon scans, silent at night – for a week.
        var office = Enumerable.Range(0, 6).SelectMany(d => new[] { (monday.AddDays(d).AddHours(14), true), (monday.AddDays(d).AddHours(2), false) })
            .OrderByDescending(h => h.Item1).ToList();
        var summary = PresenceHistory.Analyze(office);
        Assert.True(summary.Unstable);
        Assert.Contains("12:00–18:00", summary.TimeOfDay);
        Assert.Contains("nie odpowiada 00:00–06:00", summary.TimeOfDay);

        // Always present: stable, no pattern.
        var server = Enumerable.Range(0, 10).Select(i => (monday.AddHours(-6 * i), true)).ToList();
        Assert.Equal((false, null, 10, 0), (PresenceHistory.Analyze(server).Unstable, PresenceHistory.Analyze(server).TimeOfDay, PresenceHistory.Analyze(server).Seen, PresenceHistory.Analyze(server).ConsecutiveMisses));

        // Flapping without a time pattern.
        var flaky = Enumerable.Range(0, 8).Select(i => (monday.AddHours(-i * 24), i % 2 == 0)).ToList();
        Assert.True(PresenceHistory.Analyze(flaky).Unstable);
        Assert.Null(PresenceHistory.Analyze(flaky).TimeOfDay);
    }

    [Fact]
    public void A_scan_of_another_network_does_not_make_a_device_missing()
    {
        // 10.0.0.5 was seen in scan 2; scan 3 scanned only 10.0.1.0/24.
        Assert.Equal(AssetStatus.Active, AssetStatusRules.Evaluate("10.0.0.5", Scans, new HashSet<int> { 1, 2 }, 1).Status);
    }

    [Fact]
    public void Absences_list_covering_scans_without_observation()
    {
        var gaps = AssetStatusRules.Absences("10.0.0.6", Scans, new HashSet<int> { 1 }, Scans[^1].StartedAt).ToList();
        Assert.Equal([2], gaps.Select(g => g.ScanId));
    }

    private static DiscoveredHost Host(string ip, params (int Port, string? Product, string? Version, string? Thumb)[] ports) => new()
    {
        IpAddress = ip,
        Ports = ports.Select(p => new DiscoveredPort
        {
            Port = p.Port,
            Service = new DiscoveredService
            {
                ServiceName = "svc", Product = p.Product, Version = p.Version,
                Certificates = p.Thumb is null ? [] : [new Certificate { Subject = "CN=x", Issuer = "CN=x", Thumbprint = p.Thumb, NotAfter = new DateTime(2027, 1, 1) }]
            }
        }).ToList()
    };

    [Fact]
    public void Comparer_reports_ports_versions_products_certificates_and_address()
    {
        var before = Host("10.0.0.5", (22, "OpenSSH", "8.9p1", null), (80, "nginx", "1.18.0", null), (443, "nginx", "1.18.0", "AAA"), (23, null, null, null));
        var after = Host("10.0.0.9", (22, "OpenSSH", "9.6p1", null), (80, "Apache httpd", "2.4.58", null), (443, "nginx", "1.18.0", "BBB"), (3389, null, null, null));

        var changes = ObservationComparer.Compare(before, after);

        Assert.Contains(changes, c => c.Kind == AssetChangeKind.AddressChanged);
        Assert.Contains(changes, c => c.Kind == AssetChangeKind.VersionChanged && c.Port == 22 && c.Description.Contains("8.9p1 → 9.6p1"));
        Assert.Contains(changes, c => c.Kind == AssetChangeKind.ServiceChanged && c.Port == 80);
        Assert.Contains(changes, c => c.Kind == AssetChangeKind.CertificateChanged && c.Port == 443);
        Assert.Contains(changes, c => c.Kind == AssetChangeKind.PortOpened && c.Port == 3389);
        Assert.Contains(changes, c => c.Kind == AssetChangeKind.PortClosed && c.Port == 23);
    }

    [Fact]
    public void Identical_observations_have_no_changes_and_unknown_versions_are_not_changes()
    {
        Assert.Empty(ObservationComparer.Compare(Host("10.0.0.5", (22, "OpenSSH", "8.9p1", null)), Host("10.0.0.5", (22, "OpenSSH", "8.9p1", null))));
        Assert.Empty(ObservationComparer.Compare(Host("10.0.0.5", (22, "OpenSSH", "8.9p1", null)), Host("10.0.0.5", (22, "OpenSSH", null, null))));
    }

    [Fact]
    public void Ports_not_checked_by_a_later_scan_are_neither_closed_nor_reopened()
    {
        // Real sequence from a TP-Link router: standard scan (80, 81, 1900), mobile profile (checks 80 but not 81/1900), standard again.
        IReadOnlySet<int> standard = new HashSet<int> { 80, 81, 1900, 22 };
        IReadOnlySet<int> mobile = new HashSet<int> { 80, 22, 5555 };
        var history = ObservationComparer.Replay(
        [
            new PortObservation(Host("192.168.0.1", (80, null, null, null), (81, null, null, null), (1900, null, null, null)), standard),
            new PortObservation(Host("192.168.0.1", (80, null, null, null)), mobile),
            new PortObservation(Host("192.168.0.1", (80, null, null, null), (81, null, null, null), (1900, null, null, null)), standard),
        ]);

        Assert.Empty(history.Changes[1]);
        Assert.Empty(history.Changes[2]);
        Assert.Equal([80, 81, 1900], history.CurrentPorts.Select(p => p.Port));
    }

    [Fact]
    public void Port_closed_in_a_scan_that_checked_it_is_reported_and_dropped()
    {
        IReadOnlySet<int> quick = new HashSet<int> { 22, 80 };
        var history = ObservationComparer.Replay(
        [
            new PortObservation(Host("10.0.0.5", (22, "OpenSSH", "8.9p1", null), (8443, null, null, null)), null),
            new PortObservation(Host("10.0.0.5", (80, "nginx", null, null)), quick),
        ]);

        Assert.Contains(history.Changes[1], c => c.Kind == AssetChangeKind.PortClosed && c.Port == 22);
        Assert.Contains(history.Changes[1], c => c.Kind == AssetChangeKind.PortOpened && c.Port == 80);
        Assert.DoesNotContain(history.Changes[1], c => c.Port == 8443);
        Assert.Equal([80, 8443], history.CurrentPorts.Select(p => p.Port));
    }

    [Fact]
    public void Version_change_is_detected_against_the_last_scan_that_saw_the_port()
    {
        IReadOnlySet<int> other = new HashSet<int> { 443 };
        var history = ObservationComparer.Replay(
        [
            new PortObservation(Host("10.0.0.5", (22, "OpenSSH", "8.9p1", null)), null),
            new PortObservation(Host("10.0.0.5"), other),
            new PortObservation(Host("10.0.0.5", (22, "OpenSSH", "9.6p1", null)), null),
        ]);

        Assert.Empty(history.Changes[1]);
        Assert.Contains(history.Changes[2], c => c.Kind == AssetChangeKind.VersionChanged && c.Description.Contains("8.9p1 → 9.6p1"));
    }
}
