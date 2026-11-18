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
