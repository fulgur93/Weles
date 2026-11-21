using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Scheduling;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Scanning;
using Weles.Tests.Support;

namespace Weles.Tests.Scanning;

/// <summary>Large scopes in subgroups: resume points, pausing at a subgroup boundary, resuming without rescanning.</summary>
public class SubgroupTests
{
    private static ScanOptions Options() => new()
    {
        UseIcmp = false, UseMdns = false, CollectWeb = false, ConnectTimeoutMs = 400, BannerTimeoutMs = 300, ProbeTimeoutMs = 600, LivenessPorts = [1],
        SubgroupThreshold = 2, SubgroupInitialSize = 2
    };

    private sealed class RecordingSink(ScanProgress progress, int pauseAfter) : IScanSink
    {
        public ConcurrentBag<string> Hosts { get; } = [];
        public List<int> ResumePoints { get; } = [];
        public List<string> Events { get; } = [];

        public Task EventAsync(ScanEventLevel level, string message)
        {
            lock (Events) Events.Add(message);
            return Task.CompletedTask;
        }

        public Task ScopeResolvedAsync(int hostsTargeted, int portCount) => Task.CompletedTask;
        public Task NetworkAsync(string? fingerprint, IReadOnlyList<SegmentInfo> segments) => Task.CompletedTask;

        public Task HostAsync(HostScanResult host)
        {
            Hosts.Add(host.Address.ToString());
            return Task.CompletedTask;
        }

        public Task SubgroupCompletedAsync(int completedAddresses)
        {
            ResumePoints.Add(completedAddresses);
            if (completedAddresses >= pauseAfter) progress.PauseRequested = true; // e.g. the time window closed
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task A_paused_scan_continues_after_the_last_finished_subgroup()
    {
        var oui = new OuiDatabase();
        var scanner = new NetworkScanner(oui, new LocalNetworkDiscovery(oui), Options(), NullLogger.Instance);
        var request = new NetworkScanRequest([new ScopeEntry("127.0.0.0/29", false)], false, "1");

        var first = new ScanProgress(1, DateTime.UtcNow);
        var sink1 = new RecordingSink(first, pauseAfter: 2);
        var outcome = await scanner.RunAsync(request, first, sink1, CancellationToken.None);
        Assert.True(outcome.Paused);
        Assert.Equal([2], sink1.ResumePoints);
        Assert.Equal(["127.0.0.1", "127.0.0.2"], sink1.Hosts.Order());
        Assert.Contains(sink1.Events, e => e.StartsWith("Podgrupa 1: adresy 127.0.0.1–127.0.0.2"));
        Assert.Contains(sink1.Events, e => e == "Skan wstrzymany po 2 z 6 adresów – na żądanie.");

        var second = new ScanProgress(1, DateTime.UtcNow);
        var sink2 = new RecordingSink(second, pauseAfter: int.MaxValue);
        outcome = await scanner.RunAsync(request with { ResumeFrom = 2 }, second, sink2, CancellationToken.None);
        Assert.False(outcome.Paused);
        Assert.Null(outcome.Error);
        Assert.Equal(["127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6"], sink2.Hosts.Order()); // nothing scanned twice
        Assert.Equal(6, sink2.ResumePoints[^1]);
        Assert.Contains(sink2.Events, e => e.StartsWith("Wznowienie skanu od adresu 3 z 6"));
        Assert.Contains(sink2.Events, e => e.StartsWith("Podgrupa 1 po wznowieniu: adresy 127.0.0.3"));
        Assert.Contains(sink2.Events, e => e.Contains("tempo"));
    }

    [Fact]
    public async Task Engine_pauses_resumes_and_completes_the_same_scan()
    {
        await using var db = await TestDatabase.CreateAsync();
        var opts = Microsoft.Extensions.Options.Options.Create(Options());
        var oui = new OuiDatabase();
        var coordinator = new ScanCoordinator(TimeProvider.System);
        var engine = new ScanEngine(db, new ScanResultWriter(db, TimeProvider.System), oui, new LocalNetworkDiscovery(oui), opts, TimeProvider.System, NullLogger<ScanEngine>.Instance);
        var targets = new ScanTargetService(db, coordinator, opts, TimeProvider.System, NullLogger<ScanTargetService>.Instance);
        var created = await targets.CreateAsync(new ScanTargetInput("Loopback", null, "127.0.0.0/29", null, false));
        Assert.True((await targets.ApproveAsync(created.Id!.Value, confirmedAuthorization: true)).Success);

        var started = await targets.StartScanAsync(created.Id!.Value, "1");
        var scanId = started.Id!.Value;
        var progress = coordinator.GetProgress(scanId)!;
        progress.PauseRequested = true;   // the window is already closed when the scan begins
        await engine.RunAsync(scanId, progress, CancellationToken.None);
        coordinator.End(scanId);

        await using (var ctx = db.CreateDbContext())
        {
            var paused = await ctx.Scans.SingleAsync(s => s.Id == scanId);
            Assert.Equal((ScanStatus.Paused, 0, 6), (paused.Status, paused.CompletedAddresses, paused.HostsTargeted));
            Assert.Null(paused.CompletedAt);
        }

        // While paused, no new scan of the scope can start, and the scope cannot be edited.
        Assert.Contains("wstrzymany", Assert.Single((await targets.StartScanAsync(created.Id!.Value, "1")).Errors));

        Assert.True((await targets.ResumeScanAsync(scanId)).Success);
        Assert.False((await targets.ResumeScanAsync(scanId)).Success);           // already queued
        await engine.RunAsync(scanId, coordinator.GetProgress(scanId)!, CancellationToken.None);
        coordinator.End(scanId);

        await using (var ctx = db.CreateDbContext())
        {
            var scan = await ctx.Scans.Include(s => s.Events).SingleAsync(s => s.Id == scanId);
            Assert.Equal((ScanStatus.Completed, 6), (scan.Status, scan.CompletedAddresses));
            Assert.Equal(6, await ctx.DiscoveredHosts.CountAsync(h => h.ScanId == scanId));
            Assert.Contains(scan.Events, e => e.Message.StartsWith("Wznowiono skan zakresu"));
        }

        Assert.False((await targets.ResumeScanAsync(scanId)).Success);           // only paused scans
    }

    [Fact]
    public async Task A_paused_scan_cannot_resume_after_the_scope_changed_and_can_be_abandoned()
    {
        await using var db = await TestDatabase.CreateAsync();
        var opts = Microsoft.Extensions.Options.Options.Create(Options());
        var oui = new OuiDatabase();
        var coordinator = new ScanCoordinator(TimeProvider.System);
        var engine = new ScanEngine(db, new ScanResultWriter(db, TimeProvider.System), oui, new LocalNetworkDiscovery(oui), opts, TimeProvider.System, NullLogger<ScanEngine>.Instance);
        var targets = new ScanTargetService(db, coordinator, opts, TimeProvider.System, NullLogger<ScanTargetService>.Instance);
        var created = await targets.CreateAsync(new ScanTargetInput("Loopback", null, "127.0.0.0/29", null, false));
        var id = created.Id!.Value;
        Assert.True((await targets.ApproveAsync(id, confirmedAuthorization: true)).Success);
        var scanId = (await targets.StartScanAsync(id, "1")).Id!.Value;
        coordinator.GetProgress(scanId)!.PauseRequested = true;
        await engine.RunAsync(scanId, coordinator.GetProgress(scanId)!, CancellationToken.None);
        coordinator.End(scanId);

        await using (var ctx = db.CreateDbContext())
        {
            // Changed behind the service's back (the UI blocks editing while a scan is paused).
            var entry = await ctx.ScanTargetEntries.FirstAsync(e => e.ScanTargetId == id);
            entry.Value = "127.0.0.0/30";
            await ctx.SaveChangesAsync();
        }

        Assert.Contains("zmienił się", Assert.Single((await targets.ResumeScanAsync(scanId)).Errors));
        Assert.True((await targets.AbandonPausedAsync(scanId)).Success);
        await using (var ctx = db.CreateDbContext())
        {
            Assert.Equal(ScanStatus.Cancelled, (await ctx.Scans.SingleAsync(s => s.Id == scanId)).Status);
        }
    }

    [Theory]
    [InlineData(22 * 60, 6 * 60, 23, 0, true)]
    [InlineData(22 * 60, 6 * 60, 3, 30, true)]
    [InlineData(22 * 60, 6 * 60, 6, 0, false)]   // the end is exclusive
    [InlineData(22 * 60, 6 * 60, 12, 0, false)]
    [InlineData(9 * 60, 17 * 60, 9, 0, true)]
    [InlineData(9 * 60, 17 * 60, 17, 1, false)]
    public void Time_windows_may_span_midnight(int start, int end, int hour, int minute, bool inside) =>
        Assert.Equal(inside, new TimeWindow(start, end).Contains(new DateTime(2026, 11, 21, hour, minute, 0)));

    [Fact]
    public void Time_windows_are_parsed_and_validated()
    {
        Assert.True(TimeWindow.TryParse("22:00", "06:00", out var w));
        Assert.Equal("22:00–06:00", w!.ToString());
        Assert.True(TimeWindow.TryParse("", "", out var none));
        Assert.Null(none);
        Assert.False(TimeWindow.TryParse("10:00", "10:00", out _));
        Assert.False(TimeWindow.TryParse("25:00", "06:00", out _));
    }
}

public class ScheduleWindowTests
{
    private sealed class Clock(DateTime utc) : TimeProvider
    {
        public DateTime Utc { get; set; } = utc;
        public override DateTimeOffset GetUtcNow() => new(DateTime.SpecifyKind(Utc, DateTimeKind.Utc));
        public override TimeZoneInfo LocalTimeZone => TimeZoneInfo.Utc;
    }

    private sealed class NoNetworks : Weles.Infrastructure.Discovery.ICurrentNetworkProvider
    {
        public IReadOnlyList<Weles.Infrastructure.Discovery.AttachedNetwork> GetAttachedNetworks() => [];
    }

    [Fact]
    public async Task Scheduled_scans_wait_for_the_window_pause_when_it_closes_and_resume_in_the_next_one()
    {
        await using var db = await TestDatabase.CreateAsync();
        var target = TestData.ApprovedTarget();
        await using (var ctx = db.CreateDbContext())
        {
            ctx.Scans.Add(TestData.CompletedScan(target, TestData.Now.AddDays(-1)));
            await ctx.SaveChangesAsync();
        }

        var clock = new Clock(new DateTime(2026, 11, 21, 12, 0, 0, DateTimeKind.Utc));  // noon – outside 22:00–06:00
        var coordinator = new ScanCoordinator(clock);
        var targets = new ScanTargetService(db, coordinator, Microsoft.Extensions.Options.Options.Create(new ScanOptions()), clock, NullLogger<ScanTargetService>.Instance);
        var schedules = new ScheduleService(db, clock);
        var scheduler = new ScanScheduler(db, targets, coordinator, new NoNetworks(), clock, NullLogger<ScanScheduler>.Instance);
        Assert.False((await schedules.SetAsync(target.Id, ScheduleInterval.Daily, "quick", window: new TimeWindow(60, 60))).Success);
        Assert.True((await schedules.SetAsync(target.Id, ScheduleInterval.Daily, "quick", window: new TimeWindow(22 * 60, 6 * 60))).Success);
        Assert.Equal("22:00–06:00", (await schedules.ByTargetAsync())[target.Id].Window!.ToString());

        async Task MakeDue()
        {
            await using var ctx = db.CreateDbContext();
            await ctx.ScanSchedules.ExecuteUpdateAsync(u => u.SetProperty(s => s.NextRunAt, clock.Utc.AddMinutes(-1)));
        }

        // Due at noon: waits for the window instead of scanning in working hours.
        await MakeDue();
        Assert.Equal(0, await scheduler.RunDueAsync());
        Assert.StartsWith("Czeka na okno czasowe 22:00–06:00", (await schedules.ByTargetAsync())[target.Id].LastResult);

        // 23:00 – inside: starts.
        clock.Utc = new DateTime(2026, 11, 21, 23, 0, 0, DateTimeKind.Utc);
        Assert.Equal(1, await scheduler.RunDueAsync());
        int scanId;
        await using (var ctx = db.CreateDbContext())
        {
            var scan = await ctx.Scans.OrderByDescending(s => s.Id).FirstAsync();
            Assert.Equal((ScanTrigger.Scheduled, ScanStatus.Pending), (scan.Trigger, scan.Status));
            scanId = scan.Id;
            scan.Status = ScanStatus.Running;   // as the worker would
            await ctx.SaveChangesAsync();
        }

        // 06:30 – the window closed while it was running: asked to pause after the current subgroup.
        var (_, progress) = coordinator.Begin(scanId, CancellationToken.None);
        clock.Utc = new DateTime(2026, 11, 22, 6, 30, 0, DateTimeKind.Utc);
        await scheduler.RunDueAsync();
        Assert.True(progress.PauseRequested);
        Assert.Equal("okno czasowe 22:00–06:00 się skończyło; zostanie wznowiony w kolejnym oknie", progress.PauseReason);
        Assert.Contains("zostanie wstrzymany", (await schedules.ByTargetAsync())[target.Id].LastResult);

        // The engine paused it; the next due run does not start a second scan of the scope.
        coordinator.End(scanId);
        await using (var ctx = db.CreateDbContext())
        {
            var scan = await ctx.Scans.SingleAsync(s => s.Id == scanId);
            scan.Status = ScanStatus.Paused;
            scan.ScopeSnapshot = System.Text.Json.JsonSerializer.Serialize((await ctx.ScanTargetEntries.Where(e => e.ScanTargetId == target.Id).ToListAsync()).Select(e => new { e.Value, e.IsExclusion }));
            await ctx.SaveChangesAsync();
        }

        await MakeDue();
        Assert.Equal(0, await scheduler.RunDueAsync());

        // 22:15 – the next window: the paused scan is resumed (queued), not restarted.
        clock.Utc = new DateTime(2026, 11, 22, 22, 15, 0, DateTimeKind.Utc);
        Assert.Equal(1, await scheduler.RunDueAsync());
        Assert.True(coordinator.IsActive(scanId));
        Assert.StartsWith($"Wznowiono skan #{scanId}", (await schedules.ByTargetAsync())[target.Id].LastResult);
        await using (var ctx = db.CreateDbContext())
        {
            Assert.Equal(2, await ctx.Scans.CountAsync()); // the first manual one and the resumed one – no new scan
        }
    }
}
