using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Weles.Core.Entities;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Risk;
using Weles.Infrastructure.Vulnerabilities;

namespace Weles.Infrastructure.Scanning;

/// <summary>
/// What follows every finished scan – run by WELES itself or by a remote agent: detection signatures on the web
/// services, matching against the local vulnerability database, then risk assessment. Failures are logged and never undo the stored scan.
/// </summary>
public sealed class ScanPostProcessor(
    Fingerprint.SignatureService signatures,
    VulnerabilityMatchingService matching,
    RiskAssessmentService risk,
    IDbContextFactory<WelesDbContext> contextFactory,
    TimeProvider timeProvider,
    ILogger<ScanPostProcessor> logger)
{
    public async Task RunAsync(int scanId, CancellationToken ct)
    {
        try
        {
            var technologies = await signatures.EvaluateScanAsync(scanId, ct);
            if (technologies > 0) await AddEventAsync(scanId, ScanEventLevel.Info, $"Sygnatury: rozpoznano {technologies} technologii, paneli i cech usług web.", ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Signature evaluation failed for scan {ScanId}", scanId);
        }

        try
        {
            var summary = await matching.RefreshScanAsync(scanId, ct);
            await AddEventAsync(scanId, ScanEventLevel.Info,
                $"Dopasowanie podatności: {summary.Open} otwartych dla {summary.Assets} urządzeń (nowe: {summary.New}, rozwiązane: {summary.Resolved}).", ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Vulnerability matching failed for scan {ScanId}", scanId);
        }

        try
        {
            var result = await risk.RefreshScanAsync(scanId, ct);
            if (result.Assets == 0) return;
            await AddEventAsync(scanId, result.Critical > 0 ? ScanEventLevel.Warning : ScanEventLevel.Info,
                $"Ocena ryzyka: Security Posture Score {result.Posture:0}/100, urządzenia Critical: {result.Critical}, High: {result.High} (nowe problemy konfiguracji: {result.NewFindings}, rozwiązane: {result.ResolvedFindings}).", ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Risk assessment failed for scan {ScanId}", scanId);
        }
    }

    private async Task AddEventAsync(int scanId, ScanEventLevel level, string message, CancellationToken ct)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        db.ScanEvents.Add(new ScanEvent { ScanId = scanId, Level = level, Message = message, Timestamp = timeProvider.GetUtcNow().UtcDateTime });
        await db.SaveChangesAsync(ct);
    }
}
