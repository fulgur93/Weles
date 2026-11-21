using Microsoft.EntityFrameworkCore;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Infrastructure.Database;

namespace Weles.Infrastructure.Queries;

public sealed record ScanListItem(
    int Id, int TargetId, string TargetName, ScanStatus Status, ScanTrigger Trigger, string PortSpecification,
    DateTime CreatedAt, DateTime? StartedAt, DateTime? CompletedAt, int HostsTargeted, int HostsAlive, int OpenPorts, string? ErrorMessage,
    int CompletedAddresses = 0, PortEngine Engine = PortEngine.Builtin);

public sealed record ScanDetail(ScanListItem Summary, string? ScopeSnapshot, string? SettingsJson, int PortCount, IReadOnlyList<DiscoveredHost> Hosts, IReadOnlyList<ScanEvent> Events);

public sealed class ScanQueries(IDbContextFactory<WelesDbContext> contextFactory)
{
    public async Task<IReadOnlyList<ScanListItem>> ListAsync(int limit = 100, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        return await db.Scans.AsNoTracking()
            .OrderByDescending(s => s.CreatedAt)
            .Take(limit)
            .Select(s => new ScanListItem(s.Id, s.ScanTargetId, s.ScanTarget!.Name, s.Status, s.Trigger, s.PortSpecification,
                s.CreatedAt, s.StartedAt, s.CompletedAt, s.HostsTargeted, s.HostsAlive, s.OpenPorts, s.ErrorMessage, s.CompletedAddresses, s.Engine))
            .ToListAsync(ct);
    }

    /// <summary>Scope names of the given scans (for the progress indicator in the top bar).</summary>
    public async Task<Dictionary<int, string>> TargetNamesAsync(IReadOnlyCollection<int> scanIds, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        // Project in SQL – a selector passed to ToDictionaryAsync runs on entities without the ScanTarget loaded.
        var rows = await db.Scans.AsNoTracking().Where(s => scanIds.Contains(s.Id)).Select(s => new { s.Id, s.ScanTarget!.Name }).ToListAsync(ct);
        return rows.ToDictionary(r => r.Id, r => r.Name);
    }

    public async Task<ScanDetail?> GetAsync(int scanId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var summary = await db.Scans.AsNoTracking().Where(s => s.Id == scanId)
            .Select(s => new
            {
                Item = new ScanListItem(s.Id, s.ScanTargetId, s.ScanTarget!.Name, s.Status, s.Trigger, s.PortSpecification,
                    s.CreatedAt, s.StartedAt, s.CompletedAt, s.HostsTargeted, s.HostsAlive, s.OpenPorts, s.ErrorMessage, s.CompletedAddresses, s.Engine),
                s.ScopeSnapshot, s.SettingsJson, s.PortCount
            })
            .SingleOrDefaultAsync(ct);
        if (summary is null) return null;

        var hosts = await db.DiscoveredHosts.AsNoTracking().AsSplitQuery()
            .Where(h => h.ScanId == scanId)
            .Include(h => h.Ports).ThenInclude(p => p.Service).ThenInclude(s => s!.Certificates)
            .ToListAsync(ct);

        var events = await db.ScanEvents.AsNoTracking().Where(e => e.ScanId == scanId).OrderBy(e => e.Id).ToListAsync(ct);

        return new ScanDetail(summary.Item, summary.ScopeSnapshot, summary.SettingsJson, summary.PortCount,
            hosts.OrderBy(h => SortKey(h.IpAddress)).ToList(), events);
    }

    private static string SortKey(string ip) =>
        System.Net.IPAddress.TryParse(ip, out var a) ? Convert.ToHexString(a.GetAddressBytes()).PadLeft(32, '0') : ip;
}
