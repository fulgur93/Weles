using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Models;
using Weles.Core.Networking;
using Weles.Core.Risk;
using Weles.Core.Rules;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Queries;
using Weles.Infrastructure.Risk;
using Weles.Infrastructure.Scanning;
using Weles.Infrastructure.Settings;
using Weles.Infrastructure.Vulnerabilities;
using Weles.Tests.Support;

namespace Weles.Tests.Monitoring;

public class MonitoringTests
{
    private const string Home = "aa:aa:aa:00:00:01";

    private static HostScanResult Host(string ip, string mac, bool gateway, params (int Port, string Service, string? Product, string? Version, Dictionary<string, string>? Extra)[] ports) => new(
        System.Net.IPAddress.Parse(ip), DiscoveryMethod.TcpConnect, null, 64, null, mac, null, gateway,
        new HostClassification(gateway ? AssetType.Router : AssetType.LinuxHost, "Linux", 60, ["test"]),
        ports.Select(p => new PortScanResult(p.Port, "syn-ack", new ServiceProbeResult(
            new ServiceIdentification { ServiceName = p.Service, Product = p.Product, Version = p.Version, Method = "banner", Confidence = 95, Extra = p.Extra ?? [] }, null))).ToList());

    private sealed class Env : IAsyncDisposable
    {
        public required TestDatabase Db { get; init; }
        public required ScanTarget Target { get; init; }
        public required ScanResultWriter Writer { get; init; }
        public required SettingsService Settings { get; init; }

        public async Task<int> ScanAsync(DateTime at, string ports, string? network, params HostScanResult[] hosts)
        {
            int id;
            await using (var db = Db.CreateDbContext())
            {
                db.Attach(Target);
                var scan = new Scan
                {
                    ScanTarget = Target, Status = ScanStatus.Completed, PortSpecification = ports, CreatedAt = at, StartedAt = at, CompletedAt = at.AddMinutes(1),
                    ScopeSnapshot = JsonSerializer.Serialize(new[] { new { Value = "10.0.0.0/24", IsExclusion = false } }), NetworkFingerprint = network
                };
                db.Scans.Add(scan);
                await db.SaveChangesAsync();
                id = scan.Id;
            }

            foreach (var h in hosts) await Writer.SaveHostAsync(id, h);
            // Matching and risk run right after the scan, as in ScanWorker – the clock is the scan's completion.
            // A second after completion, like in the application – regression: such findings were counted for two scans.
            var clock = new FixedClock(at.AddMinutes(1).AddSeconds(1));
            await new VulnerabilityMatchingService(Db, clock, NullLogger<VulnerabilityMatchingService>.Instance).RefreshScanAsync(id);
            await new RiskAssessmentService(Db, Settings, clock, NullLogger<RiskAssessmentService>.Instance).RefreshScanAsync(id);
            return id;
        }

        public ValueTask DisposeAsync() => Db.DisposeAsync();
    }

    internal sealed class FixedClock(DateTime now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => new(DateTime.SpecifyKind(now, DateTimeKind.Utc));
    }

    private static async Task<Env> SetupAsync()
    {
        var testDb = await TestDatabase.CreateAsync();
        var target = TestData.ApprovedTarget();
        await using (var db = testDb.CreateDbContext())
        {
            db.ScanTargets.Add(target);
            await db.SaveChangesAsync();
        }

        var settings = new SettingsService(testDb, TimeProvider.System);
        await new VulnerabilityStore(testDb, settings).UpsertAsync([new Weles.Core.Vulnerabilities.VulnerabilityRecord
        {
            CveId = "CVE-2023-38408", CvssScore = 9.8, Severity = "CRITICAL", Description = "ssh-agent",
            AffectedProducts = [new("a", "openbsd", "openssh", VersionEndExcluding: "9.3")]
        }]);
        return new Env { Db = testDb, Target = target, Writer = new ScanResultWriter(testDb, TimeProvider.System), Settings = settings };
    }

    [Fact]
    public async Task Every_analysis_page_can_show_one_network_at_a_time()
    {
        await using var env = await SetupAsync();
        await env.Writer.EnsureSegmentsAsync([new SegmentInfo("10.0.0.0/24", "10.0.0.1", Home, "TP-LINK")]);
        var t0 = TestData.Now.AddDays(-2);
        var lan = await env.ScanAsync(t0, "quick", Home,
            Host("10.0.0.1", "aa:aa:aa:00:00:01", true, (80, "http", null, null, null)),
            Host("10.0.0.5", "aa:aa:aa:00:00:05", false, (22, "ssh", "OpenSSH", "8.9p1", null)));

        var externalTarget = new ScanTarget
        {
            Name = "Zewnętrzny: firma.pl", IsApproved = true, ApprovedAt = TestData.Now, AllowPublicAddresses = true, IsExternal = true, CreatedAt = TestData.Now,
            Entries = [new ScanTargetEntry { Value = "firma.pl", Kind = ScanTargetEntryKind.Domain }]
        };
        await using (var db = env.Db.CreateDbContext())
        {
            db.ScanTargets.Add(externalTarget);
            await db.SaveChangesAsync();
        }

        var ext = new Env { Db = env.Db, Target = externalTarget, Writer = env.Writer, Settings = env.Settings };
        // Telnet on a public host: a serious issue, reachability observed over the Internet.
        var external = await ext.ScanAsync(t0.AddHours(1), "quick", null, Host("93.184.216.34", null!, false, (23, "telnet", null, null, null)));

        int pc, pi;
        await using (var db = env.Db.CreateDbContext())
        {
            pc = await db.Assets.Where(a => a.PrimaryIpAddress == "10.0.0.5").Select(a => a.Id).SingleAsync();
            pi = await db.Assets.Where(a => a.PrimaryIpAddress == "93.184.216.34").Select(a => a.Id).SingleAsync();
        }

        var assets = new AssetQueries(env.Db);
        var context = await new NetworkQueries(env.Db, assets).ContextAsync();
        var home = NetworkQueries.GatewayKey(Home);
        Assert.Equal(home, context.AssetNetworkKey(pc));
        var domain = NetworkContext.ExternalPrefix + externalTarget.Id;   // each external scope (domain) is its own network
        Assert.Equal(domain, context.AssetNetworkKey(pi));
        Assert.Equal((home, domain), (context.ScanNetworkKey(lan), context.ScanNetworkKey(external)));
        Assert.Equal([home, domain], context.Networks.Select(n => n.Key));
        Assert.Equal("Internet – Zewnętrzny: firma.pl", context.LabelOf(domain));
        Assert.True(context.Includes(NetworkContext.Public, domain));      // "all public hosts" groups the domains
        Assert.False(context.OffersPublicGroup);                            // …offered only when there are several
        Assert.Equal(NetworkContext.Current, context.DefaultFilter);        // public hosts are never "the current network"
        Assert.Equal(home, context.Normalize(home));
        Assert.Equal(NetworkContext.Current, context.Normalize("gw:ff:ff:ff:ff:ff:ff"));

        // Risk: each network has its own posture; the filter limits devices and priorities.
        var risk = new RiskQueries(env.Db);
        var all = await risk.OverviewAsync(context);
        Assert.Equal([domain, home], all.Networks.Select(n => n.Latest.Key));
        var onlyPublic = await risk.OverviewAsync(context, NetworkContext.Public);
        Assert.Equal(external, Assert.Single(onlyPublic.Networks).Latest.ScanId);
        Assert.Equal([pi], onlyPublic.Assets.Select(a => a.AssetId));
        Assert.All(onlyPublic.Priorities, p => Assert.Equal(pi, p.AssetId));
        Assert.DoesNotContain((await risk.OverviewAsync(context, NetworkContext.Current)).Assets, a => a.AssetId == pi);

        // Dashboard of one network.
        var dashboard = new DashboardQueries(env.Db);
        var publicSummary = await dashboard.GetSummaryAsync(context, NetworkContext.Public);
        Assert.Equal((external, 1), (publicSummary.LastScan!.Id, publicSummary.AssetCount));
        Assert.Equal(lan, (await dashboard.GetSummaryAsync(context, home)).LastScan!.Id);
        Assert.Equal(lan, (await dashboard.GetSummaryAsync(context)).LastScan!.Id);   // all networks: the latest local scan

        // Attack paths: a public host starts on the Internet with observed reachability – never "local network".
        var topology = new TopologyQueries(env.Db, assets, risk);
        var paths = await topology.AttackPathsAsync(id => context.IncludesAsset(NetworkContext.Public, id));
        var telnet = Assert.Single(paths, p => p.Steps.Any(st => st.Port == 23));
        Assert.StartsWith("Internet → ", telnet.Title);
        Assert.Equal(95, telnet.Steps[1].Confidence);
        Assert.Contains("Połączenie przez Internet", telnet.Steps[1].Justification);
        Assert.DoesNotContain(paths, p => p.Title.StartsWith("Sieć lokalna"));
        Assert.All(await topology.AttackPathsAsync(id => context.IncludesAsset(home, id)), p => Assert.NotEqual(pi, p.TargetAssetId));

        // Vulnerabilities and topology of one network.
        var vulns = await new VulnerabilityQueries(env.Db).FindingsAsync(new VulnerabilityFindingQuery { IncludeAsset = id => context.IncludesAsset(home, id) });
        Assert.All(vulns.Items, v => Assert.NotEqual(pi, v.AssetId));
        var map = await topology.GetAsync(false, id => context.IncludesAsset(NetworkContext.Public, id));
        Assert.True(Assert.Single(map.Networks).IsPublic);
    }

    /// <summary>Regression (found on real data): a scan of public hosts replaced the home network in the dashboard, risk, monitoring and topology.</summary>
    [Fact]
    public async Task External_scans_stay_out_of_the_local_network_views()
    {
        await using var env = await SetupAsync();
        var t0 = TestData.Now.AddDays(-2);
        HostScanResult[] Lan() =>
        [
            Host("10.0.0.1", "aa:aa:aa:00:00:01", true, (80, "http", null, null, null)),
            Host("10.0.0.5", "aa:aa:aa:00:00:05", false, (22, "ssh", "OpenSSH", "8.9p1", null))
        ];
        var first = await env.ScanAsync(t0, "quick", Home, Lan());
        var second = await env.ScanAsync(t0.AddHours(1), "quick", Home, Lan());

        var externalTarget = new ScanTarget
        {
            Name = "Zewnętrzny: firma.pl", IsApproved = true, ApprovedAt = TestData.Now, AllowPublicAddresses = true, IsExternal = true, CreatedAt = TestData.Now,
            Entries = [new ScanTargetEntry { Value = "firma.pl", Kind = ScanTargetEntryKind.Domain }]
        };
        await using (var db = env.Db.CreateDbContext())
        {
            db.ScanTargets.Add(externalTarget);
            await db.SaveChangesAsync();
        }

        var ext = new Env { Db = env.Db, Target = externalTarget, Writer = env.Writer, Settings = env.Settings };
        var e1 = await ext.ScanAsync(t0.AddHours(2), "quick", null, Host("93.184.216.34", null!, false, (443, "https", null, null, null)));
        var e2 = await ext.ScanAsync(t0.AddHours(3), "quick", null, Host("93.184.216.34", null!, false, (443, "https", null, null, null), (22, "ssh", null, null, null)));

        var monitoring = new MonitoringQueries(env.Db);
        Assert.Equal((first, second), await monitoring.DefaultPairAsync());
        Assert.Equal(second, (await monitoring.LatestAsync())!.Current.Id);
        Assert.Null(await monitoring.PreviousOnSameNetworkAsync(e1));        // not the home scan
        Assert.Equal(e1, await monitoring.PreviousOnSameNetworkAsync(e2));   // same scope, no gateway
        Assert.False((await monitoring.CompareAsync(second, e1))!.SameNetwork);
        var external = (await monitoring.CompareAsync(e1, e2))!;
        Assert.True(external.SameNetwork && external.Current.IsExternal);
        Assert.Equal(1, external.Count(AssetChangeKind.PortOpened));

        var dashboard = await new DashboardQueries(env.Db).GetSummaryAsync();
        Assert.Equal(second, dashboard.LastScan!.Id);
        // Only devices of the home scan can count (the test writer stamps them with the current time, so both do);
        // the public host found later by the external scan never does – before the fix this was 3.
        Assert.Equal(2, dashboard.NewAssetsSinceLastScan);
        var risk = await new RiskQueries(env.Db).OverviewAsync();
        Assert.DoesNotContain(risk.Trend, p => p.ScanId == e1 || p.ScanId == e2);
        Assert.All(risk.Networks, n => Assert.Equal(Home, n.Latest.Fingerprint));

        var topology = new TopologyQueries(env.Db, new AssetQueries(env.Db), new RiskQueries(env.Db));
        var all = await topology.GetAsync(currentNetworkOnly: false);
        var internet = all.Networks.Single(n => n.IsPublic);
        Assert.Equal(["93.184.216.34"], internet.Devices.Select(d => d.Ip));
        Assert.Null(internet.Gateway);
        Assert.DoesNotContain(all.Networks.Where(n => !n.IsPublic).SelectMany(n => n.Devices), d => d.Ip == "93.184.216.34");
        Assert.DoesNotContain((await topology.GetAsync(currentNetworkOnly: true)).Networks, n => n.IsPublic);
    }

    [Fact]
    public async Task Comparison_answers_what_changed_since_the_last_audit()
    {
        await using var env = await SetupAsync();
        var t0 = TestData.Now.AddDays(-2);
        var first = await env.ScanAsync(t0, "standard", Home,
            Host("10.0.0.1", "aa:aa:aa:00:00:01", true, (80, "http", null, null, null), (8081, "http", null, null, null)),
            Host("10.0.0.5", "aa:aa:aa:00:00:05", false, (22, "ssh", "OpenSSH", "9.6p1", null)),
            Host("10.0.0.7", "aa:aa:aa:00:00:07", false));
        // Quick scan: does not check 8081 – the router's 8081 must not count as closed.
        var second = await env.ScanAsync(t0.AddDays(1), "quick", Home,
            Host("10.0.0.1", "aa:aa:aa:00:00:01", true, (80, "http", null, null, null), (23, "telnet", null, null, null)),
            Host("10.0.0.5", "aa:aa:aa:00:00:05", false, (22, "ssh", "OpenSSH", "8.9p1", null)),
            Host("10.0.0.9", "aa:aa:aa:00:00:09", false));

        var queries = new MonitoringQueries(env.Db);
        Assert.Equal(first, await queries.PreviousOnSameNetworkAsync(second));
        var c = (await queries.LatestAsync())!;
        Assert.True(c.SameNetwork);
        Assert.Equal(["10.0.0.9"], c.NewDevices.Select(d => d.Ip));
        Assert.Equal(["10.0.0.7"], c.MissingDevices.Select(d => d.Ip));
        Assert.Equal(1, c.Count(AssetChangeKind.PortOpened));       // telnet 23
        Assert.Equal(0, c.Count(AssetChangeKind.PortClosed));       // 8081 not checked by the quick scan
        Assert.Equal(1, c.Count(AssetChangeKind.VersionChanged));   // OpenSSH downgraded 9.6p1 → 8.9p1
        Assert.Equal(["CVE-2023-38408"], c.NewVulnerabilities.Select(v => v.CveId));
        Assert.Empty(c.ResolvedVulnerabilities);
        Assert.Contains(c.RiskChanges, r => r.Device.Ip == "10.0.0.5" && r.After > (r.Before ?? 0));
        Assert.True(c.PostureAfter < c.PostureBefore);

        // Back to the fixed version: the CVE disappears; reversed order of arguments is normalised.
        var third = await env.ScanAsync(t0.AddDays(2), "quick", Home,
            Host("10.0.0.1", "aa:aa:aa:00:00:01", true, (80, "http", null, null, null)),
            Host("10.0.0.5", "aa:aa:aa:00:00:05", false, (22, "ssh", "OpenSSH", "9.6p1", null)),
            Host("10.0.0.9", "aa:aa:aa:00:00:09", false));
        var back = (await queries.CompareAsync(third, second))!;
        Assert.Equal(second, back.Previous.Id);
        Assert.Equal(["CVE-2023-38408"], back.ResolvedVulnerabilities.Select(v => v.CveId));
        Assert.Equal(1, back.Count(AssetChangeKind.PortClosed));    // telnet closed

        var timeline = await queries.TimelineAsync();
        Assert.Equal([third, second, first], timeline.Select(t => t.Scan.Id));
        Assert.Equal((1, 1, 1), (timeline[1].NewDevices, timeline[1].MissingDevices, timeline[1].NewVulnerabilities));
        Assert.Equal((0, 1), (timeline[0].NewVulnerabilities, timeline[0].ResolvedVulnerabilities));   // counted once, in the scan that found it
        Assert.Null(timeline[2].PreviousScanId);
    }

    [Fact]
    public async Task Scans_of_another_network_are_not_compared_by_default()
    {
        await using var env = await SetupAsync();
        var home = await env.ScanAsync(TestData.Now.AddDays(-1), "quick", Home, Host("10.0.0.5", "aa:aa:aa:00:00:05", false));
        var office = await env.ScanAsync(TestData.Now, "quick", "bb:bb:bb:00:00:01", Host("10.0.0.6", "aa:aa:aa:00:00:06", false));
        var queries = new MonitoringQueries(env.Db);
        Assert.Null(await queries.PreviousOnSameNetworkAsync(office));
        Assert.Null(await queries.LatestAsync());
        Assert.False((await queries.CompareAsync(home, office))!.SameNetwork);
    }

    [Fact]
    public async Task Topology_groups_devices_around_the_gateway_and_paths_follow_the_issues()
    {
        await using var env = await SetupAsync();
        await env.ScanAsync(TestData.Now, "quick", Home,
            Host("10.0.0.1", "aa:aa:aa:00:00:01", true, (23, "telnet", null, null, null)),
            Host("10.0.0.5", "aa:aa:aa:00:00:05", false, (22, "ssh", "OpenSSH", "8.9p1", null)),
            Host("10.0.0.7", "aa:aa:aa:00:00:07", false));
        var topology = new TopologyQueries(env.Db, new AssetQueries(env.Db), new RiskQueries(env.Db));

        var model = await topology.GetAsync(currentNetworkOnly: false);
        var network = Assert.Single(model.Networks);
        Assert.Equal("10.0.0.1", network.Gateway!.Ip);
        Assert.Equal(["10.0.0.5", "10.0.0.7"], network.Devices.Select(d => d.Ip));   // riskiest first
        Assert.Contains("Telnet – logowanie bez szyfrowania", network.Gateway.Exposure);
        Assert.Contains(network.Devices[0].Exposure, e => e.StartsWith("Zaktualizuj OpenSSH"));
        Assert.Empty(network.Devices[1].Exposure);

        var paths = await topology.AttackPathsAsync();
        Assert.Contains(paths, p => p.TargetAssetId == network.Gateway.AssetId && p.Steps[2].Title.StartsWith("Telnet"));
        var ssh = paths.Single(p => p.Steps[2].CveId == "CVE-2023-38408");
        Assert.Equal(90, ssh.Steps[2].Confidence);   // confirmed match (exact version from the banner)
    }

    private sealed class Networks(params AttachedNetwork[] attached) : ICurrentNetworkProvider
    {
        public IReadOnlyList<AttachedNetwork> GetAttachedNetworks() => attached;
    }

    /// <summary>
    /// Regression (HackNation network, 2026-11-21): the interface was 10.250.192.0/20, the approved scope 10.250.192.0/24
    /// behind the same router – every device of the scan was hidden as "another network" and the pages stayed empty.
    /// </summary>
    [Fact]
    public async Task A_scope_narrower_than_the_interface_network_is_the_current_network()
    {
        await using var env = await SetupAsync();
        await env.Writer.EnsureSegmentsAsync([new SegmentInfo("10.0.0.0/24", "10.0.0.1", Home, "Cisco"), new SegmentInfo("10.0.0.0/20", "10.0.0.1", Home, "Cisco")]);
        await env.ScanAsync(TestData.Now.AddDays(-1), "quick", Home, Host("10.0.0.5", "aa:aa:aa:00:00:05", false, (22, "ssh", "OpenSSH", "8.9p1", null)));

        var here = new AssetQueries(env.Db, new Networks(new AttachedNetwork("10.0.0.0/20", Home)));
        Assert.Empty((await here.CurrentNetworkAsync()).OtherNetworkSegmentIds);
        var context = await new NetworkQueries(env.Db, here).ContextAsync();
        Assert.Contains(NetworkQueries.GatewayKey(Home), context.CurrentKeys);

        // A different router with the same addresses is still another network.
        var elsewhere = new AssetQueries(env.Db, new Networks(new AttachedNetwork("10.0.0.0/20", "cc:cc:cc:00:00:01")));
        Assert.NotEmpty((await elsewhere.CurrentNetworkAsync()).OtherNetworkSegmentIds);
        Assert.False(NetworkIdentity.CidrsOverlap("10.0.16.0/24", "10.0.0.0/20"));
        Assert.True(NetworkIdentity.CidrsOverlap("10.0.15.0/24", "10.0.0.0/20"));
    }

    /// <summary>
    /// Regression (2026-11-21): the home scope 192.168.0.0/24 was started by hand on a conference network – the same
    /// addresses belong to someone else there. A manual scan behind another router needs the user's explicit confirmation.
    /// </summary>
    [Fact]
    public async Task A_manual_scan_on_another_network_needs_confirmation()
    {
        await using var env = await SetupAsync();
        await env.ScanAsync(TestData.Now.AddDays(-1), "quick", Home, Host("10.0.0.5", "aa:aa:aa:00:00:05", false));
        ScanTargetService Service(params AttachedNetwork[] attached) => new(env.Db, new ScanCoordinator(TimeProvider.System), Options.Create(new ScanOptions()),
            TimeProvider.System, NullLogger<ScanTargetService>.Instance, new Networks(attached));

        var elsewhere = await Service(new AttachedNetwork("10.0.0.0/20", "cc:cc:cc:00:00:01")).StartScanAsync(env.Target.Id, "quick");
        Assert.False(elsewhere.Success);
        Assert.True(elsewhere.OtherNetwork);
        Assert.Contains("innej sieci", elsewhere.Errors[0]);

        var confirmed = await Service(new AttachedNetwork("10.0.0.0/20", "cc:cc:cc:00:00:01")).StartScanAsync(env.Target.Id, "quick", allowOtherNetwork: true);
        Assert.True(confirmed.Success);
        await using (var db = env.Db.CreateDbContext())
        {
            await db.Scans.Where(x => x.Id == confirmed.Id).ExecuteUpdateAsync(u => u.SetProperty(x => x.Status, ScanStatus.Cancelled));
        }

        // Home router, or a gateway WELES cannot identify (empty ARP cache): no question asked.
        Assert.True((await Service(new AttachedNetwork("10.0.0.0/24", Home)).StartScanAsync(env.Target.Id, "quick")).Success);
    }

    [Fact]
    public async Task Scheduler_scans_only_approved_scopes_on_their_own_network()
    {
        await using var env = await SetupAsync();
        var schedules = new ScheduleService(env.Db, TimeProvider.System);
        Assert.False((await schedules.SetAsync(env.Target.Id, ScheduleInterval.Daily, "quick")).Success); // never scanned: network unknown
        await env.ScanAsync(TestData.Now.AddDays(-1), "quick", Home, Host("10.0.0.5", "aa:aa:aa:00:00:05", false));
        Assert.True((await schedules.SetAsync(env.Target.Id, ScheduleInterval.Daily, "quick")).Success);
        Assert.Equal(Home, (await schedules.ByTargetAsync())[env.Target.Id].NetworkFingerprint);

        var coordinator = new ScanCoordinator(TimeProvider.System);
        var targets = new ScanTargetService(env.Db, coordinator, Options.Create(new ScanOptions()), TimeProvider.System, NullLogger<ScanTargetService>.Instance);
        var later = new FixedClock(DateTime.UtcNow.AddDays(2));
        async Task<(int Started, string? Result)> Run(params AttachedNetwork[] attached)
        {
            await using (var db = env.Db.CreateDbContext()) await db.ScanSchedules.ExecuteUpdateAsync(u => u.SetProperty(s => s.NextRunAt, DateTime.UtcNow.AddMinutes(-1)));
            var started = await new ScanScheduler(env.Db, targets, new Networks(attached), later, NullLogger<ScanScheduler>.Instance).RunDueAsync();
            return (started, (await schedules.ByTargetAsync())[env.Target.Id].LastResult);
        }

        // Same address range, other router: skipped.
        var other = await Run(new AttachedNetwork("10.0.0.0/24", "cc:cc:cc:00:00:01"));
        Assert.Equal(0, other.Started);
        Assert.Contains("innej sieci", other.Result);
        // Gateway MAC unknown (not in ARP cache) is not proof of the right network either.
        Assert.Equal(0, (await Run(new AttachedNetwork("10.0.0.0/24", null))).Started);

        var home = await Run(new AttachedNetwork("10.0.0.0/24", Home));
        Assert.Equal(1, home.Started);
        Assert.StartsWith("Uruchomiono skan #", home.Result);
        await using (var db = env.Db.CreateDbContext())
        {
            var scan = await db.Scans.OrderByDescending(s => s.Id).FirstAsync();
            Assert.Equal((ScanTrigger.Scheduled, ScanStatus.Pending), (scan.Trigger, scan.Status));
            scan.Status = ScanStatus.Cancelled;
            await db.ScanTargets.Where(t => t.Id == env.Target.Id).ExecuteUpdateAsync(u => u.SetProperty(t => t.IsApproved, false));
            await db.SaveChangesAsync();
        }

        var revoked = await Run(new AttachedNetwork("10.0.0.0/24", Home));
        Assert.Equal(0, revoked.Started);
        Assert.Contains("nie jest zatwierdzony", revoked.Result);

        Assert.True((await schedules.SetAsync(env.Target.Id, null, "quick")).Success);
        Assert.Empty(await schedules.ByTargetAsync());
    }
}

public class AttackPathTests
{
    private static PathAsset Asset(int id, AssetType type, bool gateway, bool isPublic, params PathIssue[] issues) =>
        new(id, $"dev{id}", $"10.0.0.{id}", type, AssetCriticality.Medium, gateway, isPublic, 7, "10.0.0.0/24 · TP-LINK", 5, issues);

    [Fact]
    public void Paths_are_hypotheses_with_justified_steps_and_evidence_confidence()
    {
        var paths = AttackPathEngine.Build(
        [
            Asset(5, AssetType.LinuxHost, false, false, new PathIssue("Zaktualizuj OpenSSH 8.4p1 (port 22)", 78, 22, "CVE-2023-38408", 45, "Dopasowanie wymaga weryfikacji", false)),
            Asset(1, AssetType.Router, true, false,
                new PathIssue("Telnet – logowanie bez szyfrowania", 70, 23, null, 70, "Dowód ze skanu: Port 23: usługa Telnet", false),
                new PathIssue("Usługa UPnP dostępna w sieci", 25, 1900, null, 90, "UPnP", false, IsUpnp: true)),
            Asset(9, AssetType.MobileDevice, false, false, new PathIssue("Brak nagłówków bezpieczeństwa HTTP", 10, 80, null, 90, "x", false))
        ]);

        // The 10-point issue is below the threshold; UPnP (25) gives no path of its own.
        Assert.Equal(2, paths.Count);
        Assert.All(paths, p => Assert.True(p.IsHypothetical));
        var router = paths[0];
        Assert.Equal(1, router.TargetAssetId);                          // 70 + router role beats 78 × 1 without role? 78 vs 78 → confidence decides
        Assert.Equal([PathStepKind.Entry, PathStepKind.Access, PathStepKind.Weakness, PathStepKind.Impact], router.Steps.Select(s => s.Kind));
        Assert.Null(router.Steps[0].Confidence);                         // starting point is an assumption
        Assert.Contains("Założenie", router.Steps[0].Justification);
        Assert.Contains("nie oznacza możliwości przejęcia", router.Steps[1].Justification);
        Assert.Contains("nie próbował", router.Steps[2].Justification);
        Assert.Contains("Hipoteza", router.Steps[3].Justification);
        Assert.Contains("5 urządzenia", router.Steps[3].Title);
        Assert.Equal((int)Math.Round(0.95 * 0.70 * 100), router.Confidence);

        var ssh = paths[1];
        Assert.Equal("CVE-2023-38408", ssh.Steps[2].CveId);
        Assert.Equal((int)Math.Round(0.95 * 0.45 * 100), ssh.Confidence);
    }

    [Fact]
    public void Internet_entry_only_for_public_addresses_or_upnp_and_with_low_confidence()
    {
        var withUpnp = AttackPathEngine.Build([Asset(1, AssetType.Router, true, false, new PathIssue("UPnP", 40, 1900, null, 90, "UPnP", false, IsUpnp: true))]);
        var internet = Assert.Single(withUpnp, p => p.Steps[0].Title == "Internet");
        Assert.Equal(20, internet.Steps[1].Confidence);
        Assert.True(internet.Priority < withUpnp.Single(p => p != internet).Priority);

        var publicHost = AttackPathEngine.Build([Asset(2, AssetType.Server, false, true, new PathIssue("Redis bez uwierzytelniania", 85, 6379, null, 95, "x", false))]);
        Assert.Contains(publicHost, p => p.Steps[0].Title == "Internet" && p.Steps[1].Confidence == 50);

        var lan = AttackPathEngine.Build([Asset(3, AssetType.LinuxHost, false, false, new PathIssue("Redis bez uwierzytelniania", 85, 6379, null, 95, "x", false))]);
        Assert.DoesNotContain(lan, p => p.Steps[0].Title == "Internet");
    }
}
