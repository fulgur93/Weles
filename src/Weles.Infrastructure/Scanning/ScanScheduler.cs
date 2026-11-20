using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Discovery;

namespace Weles.Infrastructure.Scanning;

public sealed record ScheduleInfo(int? Id, ScheduleInterval? Interval, string? PortSpecification, bool IsEnabled, DateTime? NextRunAt, DateTime? LastRunAt, int? LastScanId, string? LastResult, string? NetworkFingerprint);

/// <summary>Creates and changes schedules; the checks that keep automatic scans inside the user's consent live here and in <see cref="ScanScheduler"/>.</summary>
public sealed class ScheduleService(IDbContextFactory<WelesDbContext> contextFactory, TimeProvider timeProvider)
{
    public async Task<IReadOnlyDictionary<int, ScheduleInfo>> ByTargetAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        return await db.ScanSchedules.AsNoTracking().ToDictionaryAsync(s => s.ScanTargetId,
            s => new ScheduleInfo(s.Id, s.Interval, s.PortSpecification, s.IsEnabled, s.NextRunAt, s.LastRunAt, s.LastScanId, s.LastResult, s.NetworkFingerprint), ct);
    }

    /// <summary>
    /// Sets (or with <paramref name="interval"/> = null removes) the schedule of an approved scope. The scope must have been
    /// scanned at least once by the user: that scan fixes which network (gateway MAC) the automatic scans belong to.
    /// </summary>
    public async Task<OperationResult> SetAsync(int targetId, ScheduleInterval? interval, string portSpecification, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var existing = await db.ScanSchedules.SingleOrDefaultAsync(s => s.ScanTargetId == targetId, ct);
        if (interval is null)
        {
            if (existing is not null) db.ScanSchedules.Remove(existing);
            await db.SaveChangesAsync(ct);
            return OperationResult.Ok(targetId);
        }

        var target = await db.ScanTargets.AsNoTracking().SingleOrDefaultAsync(t => t.Id == targetId, ct);
        if (target is null) return OperationResult.Fail("Zakres nie istnieje.");
        if (!target.IsApproved) return OperationResult.Fail("Harmonogram można ustawić tylko dla zatwierdzonego zakresu.");
        if (!PortSpecification.TryParse(portSpecification, out _, out var portError)) return OperationResult.Fail(portError!);

        var lastScan = await db.Scans.AsNoTracking().Where(s => s.ScanTargetId == targetId && s.Status == ScanStatus.Completed)
            .OrderByDescending(s => s.StartedAt).Select(s => new { s.NetworkFingerprint }).FirstOrDefaultAsync(ct);
        if (lastScan is null) return OperationResult.Fail("Najpierw uruchom ten zakres ręcznie – pierwszy skan ustala, w której sieci (router) wolno skanować automatycznie.");

        var now = timeProvider.GetUtcNow().UtcDateTime;
        existing ??= db.ScanSchedules.Add(new ScanSchedule { ScanTargetId = targetId, PortSpecification = "", CreatedAt = now }).Entity;
        existing.Interval = interval.Value;
        existing.PortSpecification = portSpecification.Trim().ToLowerInvariant();
        existing.IsEnabled = true;
        existing.NetworkFingerprint = lastScan.NetworkFingerprint;
        existing.NextRunAt = now + ScanSchedule.Length(interval.Value);
        await db.SaveChangesAsync(ct);
        return OperationResult.Ok(existing.Id);
    }
}

/// <summary>
/// Starts scheduled scans. Never scans without approval: a due schedule is skipped (with the reason recorded) when the
/// scope is no longer approved, a scan of it is running, or this computer is not attached to the scope's network – a
/// home 192.168.0.0/24 schedule never scans an office 192.168.0.0/24.
/// </summary>
public sealed class ScanScheduler(
    IDbContextFactory<WelesDbContext> contextFactory,
    ScanTargetService targets,
    ICurrentNetworkProvider currentNetwork,
    TimeProvider timeProvider,
    ILogger<ScanScheduler> logger) : BackgroundService
{
    public static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(CheckInterval, timeProvider);
        do
        {
            try
            {
                await RunDueAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Scan scheduler failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    public async Task<int> RunDueAsync(CancellationToken ct = default)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var due = await db.ScanSchedules.Include(s => s.ScanTarget).Where(s => s.IsEnabled && s.NextRunAt <= now).ToListAsync(ct);
        var started = 0;
        foreach (var schedule in due)
        {
            schedule.NextRunAt = now + ScanSchedule.Length(schedule.Interval);
            schedule.LastRunAt = now;
            var skip = SkipReason(schedule);
            if (skip is not null)
            {
                schedule.LastResult = skip;
                logger.LogInformation("Scheduled scan of scope {TargetId} skipped: {Reason}", schedule.ScanTargetId, skip);
                continue;
            }

            var result = await targets.StartScanAsync(schedule.ScanTargetId, schedule.PortSpecification, ScanTrigger.Scheduled, ct);
            if (result.Success)
            {
                schedule.LastScanId = result.Id;
                schedule.LastResult = $"Uruchomiono skan #{result.Id}.";
                started++;
            }
            else
            {
                schedule.LastResult = "Pominięto: " + string.Join(" ", result.Errors);
            }
        }

        await db.SaveChangesAsync(ct);
        return started;
    }

    private string? SkipReason(ScanSchedule schedule)
    {
        if (schedule.ScanTarget is not { IsApproved: true }) return "Pominięto: zakres nie jest zatwierdzony.";
        if (schedule.NetworkFingerprint is null) return null;
        var attached = currentNetwork.GetAttachedNetworks();
        var onNetwork = attached.Any(n => n.GatewayMac is not null && NetworkIdentity.SameNetwork(n.GatewayMac, schedule.NetworkFingerprint));
        return onNetwork ? null : "Pominięto: komputer jest teraz w innej sieci niż ta, w której zatwierdzono i skanowano zakres (inny router).";
    }
}
