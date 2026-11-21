using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Discovery;

namespace Weles.Infrastructure.Scanning;

public sealed record ScheduleInfo(int? Id, ScheduleInterval? Interval, string? PortSpecification, bool IsEnabled, DateTime? NextRunAt, DateTime? LastRunAt, int? LastScanId, string? LastResult, string? NetworkFingerprint,
    Weles.Core.Scheduling.TimeWindow? Window = null, PortEngine Engine = PortEngine.Builtin);

/// <summary>Creates and changes schedules; the checks that keep automatic scans inside the user's consent live here and in <see cref="ScanScheduler"/>.</summary>
public sealed class ScheduleService(IDbContextFactory<WelesDbContext> contextFactory, TimeProvider timeProvider)
{
    public async Task<IReadOnlyDictionary<int, ScheduleInfo>> ByTargetAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        return await db.ScanSchedules.AsNoTracking().ToDictionaryAsync(s => s.ScanTargetId,
            s => new ScheduleInfo(s.Id, s.Interval, s.PortSpecification, s.IsEnabled, s.NextRunAt, s.LastRunAt, s.LastScanId, s.LastResult, s.NetworkFingerprint, s.Window, s.Engine), ct);
    }

    /// <summary>
    /// Sets (or with <paramref name="interval"/> = null removes) the schedule of an approved scope. The scope must have been
    /// scanned at least once by the user: that scan fixes which network (gateway MAC) the automatic scans belong to.
    /// </summary>
    /// <param name="window">Daily time window (local time) for the scans; null – any time.</param>
    public async Task<OperationResult> SetAsync(int targetId, ScheduleInterval? interval, string portSpecification, CancellationToken ct = default,
        Weles.Core.Scheduling.TimeWindow? window = null, PortEngine engine = PortEngine.Builtin)
    {
        if (window is { IsValid: false }) return OperationResult.Fail("Nieprawidłowe okno czasowe – początek i koniec muszą być różnymi godzinami.");
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
        existing.Engine = engine;
        existing.WindowStartMinute = window?.StartMinute;
        existing.WindowEndMinute = window?.EndMinute;
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
    ScanCoordinator coordinator,
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
        var local = timeProvider.GetLocalNow().DateTime;
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var started = 0;
        var resumedTargets = new HashSet<int>();

        // Time windows: a scan still running when its window closes pauses after the current subgroup; a paused scan
        // continues when the window opens again (same approval and network checks as a new scan).
        foreach (var schedule in await db.ScanSchedules.Include(s => s.ScanTarget).Where(s => s.IsEnabled && s.WindowStartMinute != null).ToListAsync(ct))
        {
            var inside = schedule.Window!.Contains(local);
            var scans = await db.Scans.Where(s => s.ScanTargetId == schedule.ScanTargetId && (s.Status == ScanStatus.Running || s.Status == ScanStatus.Paused))
                .Select(s => new { s.Id, s.Status, s.Trigger }).ToListAsync(ct);
            foreach (var running in scans.Where(s => s.Status == ScanStatus.Running && s.Trigger == ScanTrigger.Scheduled && !inside))
            {
                if (coordinator.RequestPause(running.Id, $"okno czasowe {schedule.Window} się skończyło; zostanie wznowiony w kolejnym oknie"))
                {
                    schedule.LastResult = $"Okno {schedule.Window} zamknięte – skan #{running.Id} zostanie wstrzymany po bieżącej podgrupie.";
                    logger.LogInformation("Time window of scope {TargetId} closed, pausing scan {ScanId}", schedule.ScanTargetId, running.Id);
                }
            }

            foreach (var paused in scans.Where(s => s.Status == ScanStatus.Paused && inside))
            {
                if (SkipReason(schedule) is { } skip)
                {
                    schedule.LastResult = skip;
                    continue;
                }

                var result = await targets.ResumeScanAsync(paused.Id, ct);
                schedule.LastResult = result.Success ? $"Wznowiono skan #{paused.Id} w oknie {schedule.Window}." : "Nie wznowiono: " + string.Join(" ", result.Errors);
                if (!result.Success) continue;
                started++;
                resumedTargets.Add(schedule.ScanTargetId);
            }
        }

        var due = await db.ScanSchedules.Include(s => s.ScanTarget).Where(s => s.IsEnabled && s.NextRunAt <= now).ToListAsync(ct);
        foreach (var schedule in due)
        {
            if (schedule.Window is { } window && !window.Contains(local))
            {
                // Stays due: it starts as soon as the window opens.
                schedule.LastResult = $"Czeka na okno czasowe {window}.";
                continue;
            }

            if (resumedTargets.Contains(schedule.ScanTargetId))
            {
                // This run continues the paused scan – it counts as this period's scan.
                schedule.NextRunAt = now + ScanSchedule.Length(schedule.Interval);
                continue;
            }

            if (await db.Scans.AnyAsync(s => s.ScanTargetId == schedule.ScanTargetId && s.Status == ScanStatus.Paused, ct))
            {
                // A paused scan of the scope is finished first (above) – a new one would start the scope over.
                schedule.NextRunAt = now + ScanSchedule.Length(schedule.Interval);
                schedule.LastResult = "Pominięto: poprzedni skan zakresu jest wstrzymany i zostanie dokończony.";
                continue;
            }

            schedule.NextRunAt = now + ScanSchedule.Length(schedule.Interval);
            schedule.LastRunAt = now;
            var skip = SkipReason(schedule);
            if (skip is not null)
            {
                schedule.LastResult = skip;
                logger.LogInformation("Scheduled scan of scope {TargetId} skipped: {Reason}", schedule.ScanTargetId, skip);
                continue;
            }

            var result = await targets.StartScanAsync(schedule.ScanTargetId, schedule.PortSpecification, ScanTrigger.Scheduled, ct, engine: schedule.Engine);
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
