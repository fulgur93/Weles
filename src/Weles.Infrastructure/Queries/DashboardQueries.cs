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
    /// <param name="networks">With a network context the summary covers one network (<paramref name="filter"/>): its latest scan, devices and vulnerabilities.</param>
    public async Task<DashboardSummary> GetSummaryAsync(NetworkContext? networks = null, string filter = NetworkContext.All, CancellationToken cancellationToken = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(cancellationToken);

        var completedScans = await db.Scans.CountAsync(s => s.Status == ScanStatus.Completed, cancellationToken);

        // The latest scan of the chosen network; across all networks the latest local one – scans of public hosts
        // (Attack Surface) are not "the state of the infrastructure" unless that network is chosen.
        var candidates = await db.Scans.AsNoTracking()
            .Where(s => s.Status == ScanStatus.Completed)
            .OrderByDescending(s => s.CompletedAt)
            .Select(s => new { Info = new LastScanInfo(s.Id, s.ScanTarget!.Name, s.Status, s.StartedAt, s.CompletedAt, s.HostsAlive, s.OpenPorts), s.ScanTarget.IsExternal })
            .Take(500)
            .ToListAsync(cancellationToken);
        var lastScan = (networks is null || filter == NetworkContext.All
            ? candidates.FirstOrDefault(c => !c.IsExternal)
            : candidates.FirstOrDefault(c => networks.IncludesScan(filter, c.Info.Id)))?.Info;

        bool InNetwork(int assetId) => networks is null || networks.IncludesAsset(filter, assetId);
        var assetIds = await db.Assets.Select(a => a.Id).ToListAsync(cancellationToken);
        var assetCount = assetIds.Count(InNetwork);
        var vulnerableAssets = await db.AssetVulnerabilities.Where(v => v.Status == FindingStatus.Open && v.MatchStatus != VulnerabilityMatchStatus.InsufficientData)
            .Select(v => v.AssetId).ToListAsync(cancellationToken);
        var openVulnerabilities = vulnerableAssets.Count(InNetwork);

        int activeServices = 0, criticalFindings = 0, newAssets = 0;
        double? posture = null;

        if (lastScan is not null)
        {
            activeServices = await db.DiscoveredPorts.CountAsync(p => p.Host!.ScanId == lastScan.Id && p.State == PortState.Open, cancellationToken);
            criticalFindings = await RiskQueries.CriticalIssuesAsync(db, lastScan.Id, cancellationToken);
            posture = await db.RiskScores.Where(r => r.ScanId == lastScan.Id && r.AssetId == null).Select(r => (double?)r.Score).FirstOrDefaultAsync(cancellationToken);

            if (lastScan.StartedAt is { } started)
            {
                // Devices of that scan seen for the first time – not assets found later by other scans (e.g. public hosts).
                newAssets = await db.DiscoveredHosts.Where(h => h.ScanId == lastScan.Id && h.Asset != null && h.Asset.FirstSeenAt >= started)
                    .Select(h => h.AssetId).Distinct().CountAsync(cancellationToken);
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
