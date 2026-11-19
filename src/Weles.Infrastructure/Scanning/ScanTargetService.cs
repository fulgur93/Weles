using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Infrastructure.Database;

namespace Weles.Infrastructure.Scanning;

public sealed record ScanTargetInput(string Name, string? Description, string Include, string? Exclude, bool AllowPublicAddresses);

public sealed record OperationResult(bool Success, IReadOnlyList<string> Errors, int? Id = null)
{
    public static OperationResult Ok(int? id = null) => new(true, [], id);
    public static OperationResult Fail(params string[] errors) => new(false, errors);
}

public sealed record ScopePreview(int AddressCount, IReadOnlyList<string> Warnings, IReadOnlyList<string> Errors, IReadOnlyList<string> Sample);

public sealed record ScanTargetSummary(
    int Id, string Name, string? Description, bool IsApproved, DateTime? ApprovedAt, bool AllowPublicAddresses,
    IReadOnlyList<string> Includes, IReadOnlyList<string> Excludes, int ScanCount, DateTime? LastScanAt, ScanStatus? LastScanStatus, int? ActiveScanId)
{
    public bool HasActiveScan => ActiveScanId is not null;
}

/// <summary>
/// Scope management. Rules: a scope must be approved before any scan; editing a scope revokes approval;
/// public addresses require an explicit permission flag; scopes with scan history cannot be deleted.
/// </summary>
public sealed class ScanTargetService(
    IDbContextFactory<WelesDbContext> contextFactory,
    ScanCoordinator coordinator,
    IOptions<ScanOptions> options,
    TimeProvider timeProvider,
    ILogger<ScanTargetService> logger)
{
    public async Task<IReadOnlyList<ScanTargetSummary>> ListAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var targets = await db.ScanTargets.AsNoTracking()
            .Where(t => !t.IsDemo)
            .Select(t => new
            {
                t.Id, t.Name, t.Description, t.IsApproved, t.ApprovedAt, t.AllowPublicAddresses,
                Entries = t.Entries.Select(e => new { e.Value, e.IsExclusion }).ToList(),
                ScanCount = t.Scans.Count,
                Last = t.Scans.OrderByDescending(s => s.CreatedAt).Select(s => new { s.CreatedAt, s.Status }).FirstOrDefault(),
                Active = t.Scans.Where(s => s.Status == ScanStatus.Pending || s.Status == ScanStatus.Running).OrderByDescending(s => s.Id).Select(s => (int?)s.Id).FirstOrDefault()
            })
            .OrderBy(t => t.Name)
            .ToListAsync(ct);

        return targets.Select(t => new ScanTargetSummary(t.Id, t.Name, t.Description, t.IsApproved, t.ApprovedAt, t.AllowPublicAddresses,
            t.Entries.Where(e => !e.IsExclusion).Select(e => e.Value).ToList(),
            t.Entries.Where(e => e.IsExclusion).Select(e => e.Value).ToList(),
            t.ScanCount, t.Last?.CreatedAt, t.Last?.Status, t.Active)).ToList();
    }

    public async Task<ScopePreview> PreviewAsync(ScanTargetInput input, CancellationToken ct = default)
    {
        var (entries, errors) = ParseEntries(input);
        if (errors.Count > 0) return new ScopePreview(0, [], errors, []);

        var resolution = await ScopeResolver.ResolveAsync(
            entries.Select(e => new ScopeEntry(e.Value, e.IsExclusion)), input.AllowPublicAddresses, options.Value.MaxHostsPerScan,
            async (domain, token) => await Dns.GetHostAddressesAsync(domain, token), ct);

        return new ScopePreview(resolution.Addresses.Count, resolution.Warnings, resolution.Errors,
            resolution.Addresses.Take(5).Select(a => a.ToString()).ToList());
    }

    public async Task<OperationResult> CreateAsync(ScanTargetInput input, CancellationToken ct = default)
    {
        var (entries, errors) = ParseEntries(input);
        if (errors.Count > 0) return new OperationResult(false, errors);

        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var now = Now;
        var target = new ScanTarget
        {
            Name = input.Name.Trim(), Description = Normalize(input.Description), AllowPublicAddresses = input.AllowPublicAddresses,
            CreatedAt = now, UpdatedAt = now, Entries = entries
        };
        db.ScanTargets.Add(target);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Scan scope {TargetId} \"{Name}\" created with {Count} entries", target.Id, target.Name, entries.Count);
        return OperationResult.Ok(target.Id);
    }

    /// <summary>Any change to the scope revokes its approval.</summary>
    public async Task<OperationResult> UpdateAsync(int id, ScanTargetInput input, CancellationToken ct = default)
    {
        var (entries, errors) = ParseEntries(input);
        if (errors.Count > 0) return new OperationResult(false, errors);

        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var target = await db.ScanTargets.Include(t => t.Entries).SingleOrDefaultAsync(t => t.Id == id, ct);
        if (target is null) return OperationResult.Fail("Zakres nie istnieje.");
        if (await HasActiveScanAsync(db, id, ct)) return OperationResult.Fail("Nie można edytować zakresu podczas trwającego skanu.");

        db.ScanTargetEntries.RemoveRange(target.Entries);
        target.Entries = entries;
        target.Name = input.Name.Trim();
        target.Description = Normalize(input.Description);
        target.AllowPublicAddresses = input.AllowPublicAddresses;
        target.IsApproved = false;
        target.ApprovedAt = null;
        target.UpdatedAt = Now;
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Scan scope {TargetId} updated – approval revoked", id);
        return OperationResult.Ok(id);
    }

    public async Task<OperationResult> ApproveAsync(int id, bool confirmedAuthorization, CancellationToken ct = default)
    {
        if (!confirmedAuthorization) return OperationResult.Fail("Potwierdź, że masz uprawnienia do skanowania wszystkich zasobów w tym zakresie.");

        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var target = await db.ScanTargets.SingleOrDefaultAsync(t => t.Id == id, ct);
        if (target is null) return OperationResult.Fail("Zakres nie istnieje.");

        target.IsApproved = true;
        target.ApprovedAt = Now;
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Scan scope {TargetId} \"{Name}\" approved by the user", id, target.Name);
        return OperationResult.Ok(id);
    }

    public async Task<OperationResult> RevokeApprovalAsync(int id, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var updated = await db.ScanTargets.Where(t => t.Id == id).ExecuteUpdateAsync(u => u.SetProperty(t => t.IsApproved, false).SetProperty(t => t.ApprovedAt, (DateTime?)null), ct);
        logger.LogInformation("Scan scope {TargetId} approval revoked", id);
        return updated == 1 ? OperationResult.Ok(id) : OperationResult.Fail("Zakres nie istnieje.");
    }

    public async Task<OperationResult> DeleteAsync(int id, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        if (await db.Scans.AnyAsync(s => s.ScanTargetId == id, ct))
        {
            return OperationResult.Fail("Zakres ma historię skanów – nie można go usunąć (historia audytów musi zostać zachowana).");
        }

        var deleted = await db.ScanTargets.Where(t => t.Id == id).ExecuteDeleteAsync(ct);
        return deleted == 1 ? OperationResult.Ok() : OperationResult.Fail("Zakres nie istnieje.");
    }

    public async Task<OperationResult> StartScanAsync(int targetId, string portSpecification, ScanTrigger trigger = ScanTrigger.Manual, CancellationToken ct = default)
    {
        if (!PortSpecification.TryParse(portSpecification, out _, out var portError)) return OperationResult.Fail(portError!);

        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var target = await db.ScanTargets.SingleOrDefaultAsync(t => t.Id == targetId, ct);
        if (target is null) return OperationResult.Fail("Zakres nie istnieje.");
        if (!target.IsApproved) return OperationResult.Fail("Zakres nie jest zatwierdzony. Zatwierdź go przed uruchomieniem skanu.");
        if (await HasActiveScanAsync(db, targetId, ct)) return OperationResult.Fail("Dla tego zakresu trwa już skan.");

        var scan = new Scan
        {
            ScanTargetId = targetId, Status = ScanStatus.Pending, Trigger = trigger,
            PortSpecification = portSpecification.Trim().ToLowerInvariant(), CreatedAt = Now
        };
        db.Scans.Add(scan);
        await db.SaveChangesAsync(ct);
        await coordinator.EnqueueAsync(scan.Id, ct);
        logger.LogInformation("Scan {ScanId} queued for scope {TargetId}", scan.Id, targetId);
        return OperationResult.Ok(scan.Id);
    }

    public bool StopScan(int scanId)
    {
        logger.LogInformation("Stop requested for scan {ScanId}", scanId);
        return coordinator.RequestStop(scanId);
    }

    private static Task<bool> HasActiveScanAsync(WelesDbContext db, int targetId, CancellationToken ct) =>
        db.Scans.AnyAsync(s => s.ScanTargetId == targetId && (s.Status == ScanStatus.Pending || s.Status == ScanStatus.Running), ct);

    internal static (List<ScanTargetEntry> Entries, List<string> Errors) ParseEntries(ScanTargetInput input)
    {
        var errors = new List<string>();
        var entries = new List<ScanTargetEntry>();

        if (string.IsNullOrWhiteSpace(input.Name)) errors.Add("Podaj nazwę zakresu.");
        else if (input.Name.Trim().Length > 200) errors.Add("Nazwa może mieć maksymalnie 200 znaków.");

        void Add(string? text, bool exclusion)
        {
            foreach (var raw in TargetParser.SplitEntries(text))
            {
                if (!TargetParser.TryParse(raw, out var parsed, out var error))
                {
                    errors.Add(error!);
                    continue;
                }

                if (!exclusion && !input.AllowPublicAddresses && IsPublicLiteral(parsed))
                {
                    errors.Add($"{parsed.Normalized} zawiera adresy publiczne. Zaznacz zgodę na skanowanie adresów publicznych tylko, jeśli masz do nich uprawnienia.");
                    continue;
                }

                if (entries.Any(e => e.Value == parsed.Normalized && e.IsExclusion == exclusion)) continue;
                entries.Add(new ScanTargetEntry { Value = parsed.Normalized, Kind = parsed.Kind, IsExclusion = exclusion });
            }
        }

        Add(input.Include, exclusion: false);
        Add(input.Exclude, exclusion: true);

        if (!entries.Any(e => !e.IsExclusion) && errors.Count == 0) errors.Add("Dodaj co najmniej jeden adres, sieć, zakres lub domenę.");
        if (entries.Count > 256) errors.Add("Zakres może zawierać maksymalnie 256 wpisów.");
        return (entries, errors);
    }

    private static bool IsPublicLiteral(ParsedTarget parsed)
    {
        if (parsed.Ipv6Address is { } v6) return AddressClassifier.IsPublic(v6);
        if (parsed.Ipv4Range is not { } r) return false;
        return AddressClassifier.IsPublic(Ipv4.FromUInt(r.Start)) || AddressClassifier.IsPublic(Ipv4.FromUInt(r.End));
    }

    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim()[..Math.Min(value.Trim().Length, 2000)];

    private DateTime Now => timeProvider.GetUtcNow().UtcDateTime;
}
