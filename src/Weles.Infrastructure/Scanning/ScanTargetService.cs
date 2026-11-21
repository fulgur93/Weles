using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Discovery;

namespace Weles.Infrastructure.Scanning;

public sealed record ScanTargetInput(string Name, string? Description, string Include, string? Exclude, bool AllowPublicAddresses);

/// <param name="OtherNetwork">The scan was refused because this computer is now on another network (another router) –
/// the user may confirm and start it anyway.</param>
public sealed record OperationResult(bool Success, IReadOnlyList<string> Errors, int? Id = null, bool OtherNetwork = false)
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
    ILogger<ScanTargetService> logger,
    ICurrentNetworkProvider? currentNetwork = null)
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

    /// <param name="allowOtherNetwork">The user confirmed scanning although the router differs from the scope's last scan.</param>
    public async Task<OperationResult> StartScanAsync(int targetId, string portSpecification, ScanTrigger trigger = ScanTrigger.Manual, CancellationToken ct = default,
        bool allowOtherNetwork = false, PortEngine engine = PortEngine.Builtin)
    {
        if (!PortSpecification.TryParse(portSpecification, out _, out var portError)) return OperationResult.Fail(portError!);

        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var target = await db.ScanTargets.SingleOrDefaultAsync(t => t.Id == targetId, ct);
        if (target is null) return OperationResult.Fail("Zakres nie istnieje.");
        if (!target.IsApproved) return OperationResult.Fail("Zakres nie jest zatwierdzony. Zatwierdź go przed uruchomieniem skanu.");
        if (await db.Scans.AsNoTracking().Where(s => s.ScanTargetId == targetId && s.Status == ScanStatus.Paused).Select(s => (int?)s.Id).FirstOrDefaultAsync(ct) is { } paused)
        {
            return OperationResult.Fail($"Skan #{paused} tego zakresu jest wstrzymany – wznów go albo zakończ, zanim uruchomisz nowy.");
        }

        if (await HasActiveScanAsync(db, targetId, ct)) return OperationResult.Fail("Dla tego zakresu trwa już skan.");
        var otherNetwork = await OtherNetworkAsync(db, target, ct);
        if (!allowOtherNetwork && otherNetwork is { } other)
        {
            logger.LogWarning("Scan of scope {TargetId} refused: this computer is on another network than the scope's last scan", targetId);
            return new OperationResult(false, [other], OtherNetwork: true);
        }

        var scan = new Scan
        {
            ScanTargetId = targetId, Status = ScanStatus.Pending, Trigger = trigger, Engine = engine,
            PortSpecification = portSpecification.Trim().ToLowerInvariant(), CreatedAt = Now
        };
        db.Scans.Add(scan);
        await db.SaveChangesAsync(ct);
        if (otherNetwork is not null)
        {
            // The user forced a scope from a different network: keep the reason on the scan itself, where the empty
            // results are visible later, not only in the application log.
            db.ScanEvents.Add(new ScanEvent { ScanId = scan.Id, Level = ScanEventLevel.Warning, Timestamp = Now,
                Message = $"Skan wymuszony mimo ostrzeżenia: {otherNetwork} Brak wyników jest spodziewany, dopóki komputer nie będzie w tej sieci." });
            await db.SaveChangesAsync(ct);
        }

        await coordinator.EnqueueAsync(scan.Id, ct);
        logger.LogInformation("Scan {ScanId} queued for scope {TargetId}", scan.Id, targetId);
        return OperationResult.Ok(scan.Id);
    }

    /// <summary>
    /// Continues a paused scan from its last finished subgroup. The same checks as a new scan: the scope must still be
    /// approved and unchanged, and this computer must be on the network where the scan started (same router).
    /// </summary>
    public async Task<OperationResult> ResumeScanAsync(int scanId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var scan = await db.Scans.Include(s => s.ScanTarget!).ThenInclude(t => t.Entries).SingleOrDefaultAsync(s => s.Id == scanId, ct);
        if (scan is null) return OperationResult.Fail("Skan nie istnieje.");
        if (scan.Status != ScanStatus.Paused) return OperationResult.Fail("Wznowić można tylko wstrzymany skan.");
        var target = scan.ScanTarget!;
        if (!target.IsApproved) return OperationResult.Fail("Zakres nie jest już zatwierdzony – wstrzymanego skanu nie można wznowić.");
        if (scan.ScopeSnapshot != System.Text.Json.JsonSerializer.Serialize(target.Entries.Select(e => new { e.Value, e.IsExclusion })))
        {
            return OperationResult.Fail("Zakres zmienił się od rozpoczęcia skanu – zakończ ten skan i uruchom nowy.");
        }

        if (await db.Scans.AnyAsync(s => s.ScanTargetId == scan.ScanTargetId && s.Id != scanId && (s.Status == ScanStatus.Pending || s.Status == ScanStatus.Running), ct))
        {
            return OperationResult.Fail("Dla tego zakresu trwa już skan.");
        }

        if (currentNetwork is not null && !target.IsExternal && scan.NetworkFingerprint is { } network)
        {
            var gateways = currentNetwork.GetAttachedNetworks().Where(n => n.GatewayMac is not null).ToList();
            if (gateways.Count > 0 && !gateways.Any(n => NetworkIdentity.SameNetwork(n.GatewayMac, network)))
            {
                return OperationResult.Fail("Komputer jest teraz w innej sieci niż ta, w której skan się zaczął – wznowienie odrzucone.");
            }
        }

        if (coordinator.IsActive(scanId)) return OperationResult.Fail("Skan jest już w kolejce.");
        await coordinator.EnqueueAsync(scanId, ct);
        logger.LogInformation("Scan {ScanId} resumed", scanId);
        return OperationResult.Ok(scanId);
    }

    public bool PauseScan(int scanId) => coordinator.RequestPause(scanId);

    /// <summary>Ends a paused scan for good: it stays "cancelled" with the subgroups it finished.</summary>
    public async Task<OperationResult> AbandonPausedAsync(int scanId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var scan = await db.Scans.SingleOrDefaultAsync(s => s.Id == scanId && s.Status == ScanStatus.Paused, ct);
        if (scan is null || coordinator.IsActive(scanId)) return OperationResult.Fail("Ten skan nie jest wstrzymany.");
        scan.Status = ScanStatus.Cancelled;
        scan.CompletedAt = Now;
        db.ScanEvents.Add(new ScanEvent { ScanId = scanId, Level = ScanEventLevel.Warning, Timestamp = Now,
            Message = $"Wstrzymany skan zakończony bez wznowienia – zachowano wyniki dla {scan.CompletedAddresses} z {scan.HostsTargeted} adresów." });
        await db.SaveChangesAsync(ct);
        return OperationResult.Ok(scanId);
    }

    public bool StopScan(int scanId)
    {
        logger.LogInformation("Stop requested for scan {ScanId}", scanId);
        return coordinator.RequestStop(scanId);
    }

    /// <summary>
    /// A local scope was last scanned behind a known router, and this computer is now behind another one (e.g. the home
    /// scope 192.168.0.0/24 started on a conference network): the same addresses belong to someone else here. Unknown
    /// gateways (empty ARP cache) and Internet scopes are not judged.
    /// </summary>
    private async Task<string?> OtherNetworkAsync(WelesDbContext db, ScanTarget target, CancellationToken ct)
    {
        if (currentNetwork is null || target.IsExternal) return null;
        var last = await db.Scans.AsNoTracking()
            .Where(s => s.ScanTargetId == target.Id && s.Status == ScanStatus.Completed && s.NetworkFingerprint != null)
            .OrderByDescending(s => s.StartedAt).Select(s => s.NetworkFingerprint).FirstOrDefaultAsync(ct);
        if (last is null) return null;
        var gateways = currentNetwork.GetAttachedNetworks().Where(n => n.GatewayMac is not null).ToList();
        if (gateways.Count == 0 || gateways.Any(n => NetworkIdentity.SameNetwork(n.GatewayMac, last))) return null;
        return $"Komputer jest teraz w innej sieci (router {gateways[0].GatewayMac}) niż ta, w której zakres „{target.Name}” był skanowany (router {last.Split(',')[0]}). "
               + "Te same adresy należą tu do kogoś innego – skanuj tylko sieć, do której masz uprawnienia.";
    }

    private static Task<bool> HasActiveScanAsync(WelesDbContext db, int targetId, CancellationToken ct) =>
        db.Scans.AnyAsync(s => s.ScanTargetId == targetId && (s.Status == ScanStatus.Pending || s.Status == ScanStatus.Running || s.Status == ScanStatus.Paused), ct);

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
