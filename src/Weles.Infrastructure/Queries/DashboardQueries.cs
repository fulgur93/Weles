using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Weles.Core.Enums;
using Weles.Core.Models;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Settings;

namespace Weles.Infrastructure.Queries;

/// <summary>Read model for the dashboard. All values come from the database – nothing is synthesized.</summary>
public sealed class DashboardQueries(IDbContextFactory<WelesDbContext> contextFactory)
{
    public async Task<DashboardSummary> GetSummaryAsync(CancellationToken cancellationToken = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(cancellationToken);

        var completedScans = await db.Scans.CountAsync(s => s.Status == ScanStatus.Completed, cancellationToken);

        var lastScan = await db.Scans.AsNoTracking()
            .Where(s => s.Status == ScanStatus.Completed)
            .OrderByDescending(s => s.CompletedAt)
            .Select(s => new LastScanInfo(s.Id, s.ScanTarget!.Name, s.Status, s.StartedAt, s.CompletedAt, s.HostsAlive, s.OpenPorts))
            .FirstOrDefaultAsync(cancellationToken);

        var assetCount = await db.Assets.CountAsync(cancellationToken);
        var openVulnerabilities = await db.AssetVulnerabilities.CountAsync(v => v.Status == FindingStatus.Open && v.MatchStatus != VulnerabilityMatchStatus.InsufficientData, cancellationToken);

        int activeServices = 0, criticalFindings = 0, newAssets = 0;
        double? posture = null;

        if (lastScan is not null)
        {
            activeServices = await db.DiscoveredPorts.CountAsync(p => p.Host!.ScanId == lastScan.Id && p.State == PortState.Open, cancellationToken);
            criticalFindings = await RiskQueries.CriticalIssuesAsync(db, lastScan.Id, cancellationToken);
            posture = await db.RiskScores.Where(r => r.ScanId == lastScan.Id && r.AssetId == null).Select(r => (double?)r.Score).FirstOrDefaultAsync(cancellationToken);

            if (lastScan.StartedAt is { } started)
            {
                newAssets = await db.Assets.CountAsync(a => a.FirstSeenAt >= started, cancellationToken);
            }
        }

        var vulnDbUpdated = await db.Settings.AsNoTracking()
            .Where(s => s.Key == SettingsService.Keys.VulnerabilityDatabaseUpdatedAt)
            .Select(s => s.Value)
            .FirstOrDefaultAsync(cancellationToken);

        DateTime? vulnDbUpdatedAt = DateTime.TryParse(vulnDbUpdated, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed)
            ? parsed
            : null;

        return new DashboardSummary(assetCount, activeServices, openVulnerabilities, criticalFindings, newAssets, completedScans, lastScan, posture, vulnDbUpdatedAt);
    }
}
