using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Infrastructure.Database;

namespace Weles.Infrastructure.Scanning;

/// <summary>Executes queued scans one at a time, independently of any browser session.</summary>
public sealed class ScanWorker(
    ScanCoordinator coordinator,
    IServiceProvider services,
    IDbContextFactory<WelesDbContext> contextFactory,
    TimeProvider timeProvider,
    ILogger<ScanWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await RecoverInterruptedScansAsync(stoppingToken);

        await foreach (var scanId in coordinator.DequeueAllAsync(stoppingToken))
        {
            var (cts, progress) = coordinator.Begin(scanId, stoppingToken);
            try
            {
                var engine = services.GetRequiredService<ScanEngine>();
                await engine.RunAsync(scanId, progress, cts.Token);
                progress.Phase = ScanPhase.Finishing;
                progress.Activity = "Dopasowanie podatności i ocena ryzyka";
                await MatchVulnerabilitiesAsync(scanId, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
            {
                logger.LogError(ex, "Unhandled error while running scan {ScanId}", scanId);
            }
            finally
            {
                coordinator.End(scanId);
            }
        }
    }

    /// <summary>Matches the devices of a finished scan against the local vulnerability database, then assesses their risk.</summary>
    private async Task MatchVulnerabilitiesAsync(int scanId, CancellationToken ct)
    {
        try
        {
            var summary = await services.GetRequiredService<Vulnerabilities.VulnerabilityMatchingService>().RefreshScanAsync(scanId, ct);
            await using var db = await contextFactory.CreateDbContextAsync(ct);
            db.ScanEvents.Add(new ScanEvent
            {
                ScanId = scanId,
                Level = ScanEventLevel.Info,
                Message = $"Dopasowanie podatności: {summary.Open} otwartych dla {summary.Assets} urządzeń (nowe: {summary.New}, rozwiązane: {summary.Resolved}).",
                Timestamp = timeProvider.GetUtcNow().UtcDateTime
            });
            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Vulnerability matching failed for scan {ScanId}", scanId);
        }

        try
        {
            var risk = await services.GetRequiredService<Risk.RiskAssessmentService>().RefreshScanAsync(scanId, ct);
            if (risk.Assets == 0) return;
            await using var db = await contextFactory.CreateDbContextAsync(ct);
            db.ScanEvents.Add(new ScanEvent
            {
                ScanId = scanId,
                Level = risk.Critical > 0 ? ScanEventLevel.Warning : ScanEventLevel.Info,
                Message = $"Ocena ryzyka: Security Posture Score {risk.Posture:0}/100, urządzenia Critical: {risk.Critical}, High: {risk.High} (nowe problemy konfiguracji: {risk.NewFindings}, rozwiązane: {risk.ResolvedFindings}).",
                Timestamp = timeProvider.GetUtcNow().UtcDateTime
            });
            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Risk assessment failed for scan {ScanId}", scanId);
        }
    }

    /// <summary>Scans interrupted by an application shutdown are marked, never silently left "running".</summary>
    private async Task RecoverInterruptedScansAsync(CancellationToken ct)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var stale = await db.Scans.Where(s => s.Status == ScanStatus.Running || s.Status == ScanStatus.Pending).ToListAsync(ct);
        foreach (var scan in stale)
        {
            var wasRunning = scan.Status == ScanStatus.Running;
            scan.Status = wasRunning ? ScanStatus.Failed : ScanStatus.Cancelled;
            scan.CompletedAt = timeProvider.GetUtcNow().UtcDateTime;
            scan.ErrorMessage = wasRunning ? "Skan przerwany – aplikacja została zamknięta w trakcie skanowania." : "Skan oczekujący anulowany po ponownym uruchomieniu aplikacji.";
            db.ScanEvents.Add(new ScanEvent { ScanId = scan.Id, Level = ScanEventLevel.Warning, Message = scan.ErrorMessage, Timestamp = scan.CompletedAt.Value });
        }

        if (stale.Count > 0)
        {
            await db.SaveChangesAsync(ct);
            logger.LogWarning("Marked {Count} interrupted scan(s) after restart", stale.Count);
        }
    }
}
