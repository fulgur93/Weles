using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.External;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Scanning;

namespace Weles.Infrastructure.External;

public sealed record ExternalTargetInput(string Name, string? Description, bool ConfirmedAuthorization, bool UseCertificateTransparency, string? KnownHosts);

public sealed record ExternalTargetSummary(
    int Id, string Name, ExternalTargetKind Kind, string? Description, DateTime AuthorizedAt, bool UseCertificateTransparency, string? KnownHosts,
    int? ScanTargetId, bool? ScopeApproved, ExternalAnalysisStatus? LastStatus, DateTime? LastAnalysisAt, int LastHostCount, int LastFindingCount);

public sealed record ExternalAnalysisRef(int Id, ExternalAnalysisStatus Status, DateTime StartedAt, DateTime? CompletedAt, int HostCount, int FindingCount, string? Error);

public sealed record ExternalAnalysisView(ExternalAnalysisRef Analysis, ExternalSnapshot? Snapshot, IReadOnlyList<ExternalFinding> Findings);

public sealed record ExternalServiceView(int Port, string? Service, string? Product, string? Version, bool IsTls, bool IsAdministrative,
    string? CertificateSubject, DateTime? CertificateNotAfter, bool CertificateSelfSigned, bool? CertificateHostnameMatches);

public sealed record ExternalRiskView(string Title, RiskLevel Level, double Score, string? Evidence, int? Port);

public sealed record ExternalActiveHost(int? AssetId, string Ip, string? Hostname, IReadOnlyList<ExternalServiceView> Services, IReadOnlyList<ExternalRiskView> Findings);

public sealed record ExternalActiveResult(int ScanId, DateTime At, ScanStatus Status, string PortSpecification, int HostsTargeted, IReadOnlyList<ExternalActiveHost> Hosts);

/// <summary>
/// External attack surface. Passive analysis (DNS records, Certificate Transparency) never connects to the user's hosts.
/// Active scanning is never started from here: the user selects hosts, WELES creates an unapproved scope with permission
/// for public addresses, and the scan runs only after the user approves that scope in Network Discovery.
/// </summary>
public sealed class ExternalSurfaceService(
    IDbContextFactory<WelesDbContext> contextFactory,
    DnsLookup dns,
    ICertificateTransparencySource ct,
    ScanTargetService scopes,
    IOptions<ExternalOptions> options,
    TimeProvider timeProvider,
    IHostApplicationLifetime lifetime,
    ILogger<ExternalSurfaceService> logger)
{
    private readonly ConcurrentDictionary<int, Task> _running = new();
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    public IReadOnlyList<IPEndPoint> Resolvers => dns.Servers;

    public async Task<IReadOnlyList<ExternalTargetSummary>> ListAsync(CancellationToken token = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(token);
        var rows = await db.ExternalTargets.AsNoTracking()
            .Select(t => new
            {
                t.Id, t.Name, t.Kind, t.Description, t.AuthorizedAt, t.UseCertificateTransparency, t.KnownHosts, t.ScanTargetId,
                Approved = t.ScanTarget == null ? (bool?)null : t.ScanTarget.IsApproved,
                Last = t.Analyses.OrderByDescending(a => a.Id).Select(a => new { a.Status, a.StartedAt, a.HostCount, a.FindingCount }).FirstOrDefault()
            })
            .ToListAsync(token);
        return rows.OrderBy(r => r.Name).Select(r => new ExternalTargetSummary(r.Id, r.Name, r.Kind, r.Description, r.AuthorizedAt, r.UseCertificateTransparency, r.KnownHosts,
            r.ScanTargetId, r.Approved, r.Last?.Status, r.Last?.StartedAt, r.Last?.HostCount ?? 0, r.Last?.FindingCount ?? 0)).ToList();
    }

    public async Task<OperationResult> AddAsync(ExternalTargetInput input, CancellationToken token = default)
    {
        if (!input.ConfirmedAuthorization)
        {
            return OperationResult.Fail("Potwierdź, że domena lub adres należy do Ciebie albo masz pisemną zgodę właściciela.");
        }

        string name;
        ExternalTargetKind kind;
        if (IPAddress.TryParse(input.Name.Trim(), out _))
        {
            if (!DomainNames.TryParsePublicAddress(input.Name, out var address, out var addressError)) return OperationResult.Fail(addressError!);
            (name, kind) = (address.ToString(), ExternalTargetKind.Address);
        }
        else
        {
            if (!DomainNames.TryNormalize(input.Name, out var domain, out var domainError)) return OperationResult.Fail(domainError!);
            (name, kind) = (domain, ExternalTargetKind.Domain);
        }

        var (known, knownErrors) = ParseKnownHosts(input.KnownHosts, name, kind);
        if (knownErrors.Count > 0) return new OperationResult(false, knownErrors);

        await using var db = await contextFactory.CreateDbContextAsync(token);
        if (await db.ExternalTargets.AnyAsync(t => t.Name == name, token)) return OperationResult.Fail($"{name} jest już na liście.");

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var target = new ExternalTarget
        {
            Name = name, Kind = kind, Description = string.IsNullOrWhiteSpace(input.Description) ? null : input.Description.Trim(),
            AuthorizedAt = now, CreatedAt = now, UseCertificateTransparency = kind == ExternalTargetKind.Domain && input.UseCertificateTransparency,
            KnownHosts = known.Count == 0 ? null : string.Join('\n', known)
        };
        db.ExternalTargets.Add(target);
        await db.SaveChangesAsync(token);
        logger.LogInformation("External target {Id} added ({Kind}); ownership confirmed by the user", target.Id, kind);
        return OperationResult.Ok(target.Id);
    }

    public async Task<OperationResult> UpdateSettingsAsync(int id, bool useCertificateTransparency, string? knownHosts, CancellationToken token = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(token);
        var target = await db.ExternalTargets.SingleOrDefaultAsync(t => t.Id == id, token);
        if (target is null) return OperationResult.Fail("Cel nie istnieje.");
        var (known, errors) = ParseKnownHosts(knownHosts, target.Name, target.Kind);
        if (errors.Count > 0) return new OperationResult(false, errors);
        target.UseCertificateTransparency = target.Kind == ExternalTargetKind.Domain && useCertificateTransparency;
        target.KnownHosts = known.Count == 0 ? null : string.Join('\n', known);
        await db.SaveChangesAsync(token);
        return OperationResult.Ok(id);
    }

    /// <summary>Removes the target and its passive analyses. The scan scope and its scan history stay.</summary>
    public async Task<OperationResult> DeleteAsync(int id, CancellationToken token = default)
    {
        if (_running.ContainsKey(id)) return OperationResult.Fail("Poczekaj na zakończenie analizy.");
        await using var db = await contextFactory.CreateDbContextAsync(token);
        var target = await db.ExternalTargets.Include(t => t.Analyses).SingleOrDefaultAsync(t => t.Id == id, token);
        if (target is null) return OperationResult.Fail("Cel nie istnieje.");
        db.ExternalTargets.Remove(target);
        await db.SaveChangesAsync(token);
        return OperationResult.Ok();
    }

    public bool IsRunning(int targetId) => _running.ContainsKey(targetId);

    /// <summary>Starts a passive analysis in the background; the result is stored even if the page is closed.</summary>
    public async Task<OperationResult> StartPassiveAsync(int targetId, CancellationToken token = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(token);
        var target = await db.ExternalTargets.AsNoTracking().SingleOrDefaultAsync(t => t.Id == targetId, token);
        if (target is null) return OperationResult.Fail("Cel nie istnieje.");
        if (dns.Servers.Count == 0) return OperationResult.Fail("Nie znaleziono serwera DNS w ustawieniach systemu.");

        var analysis = new ExternalAnalysis { ExternalTargetId = targetId, Status = ExternalAnalysisStatus.Running, StartedAt = timeProvider.GetUtcNow().UtcDateTime };
        db.ExternalAnalyses.Add(analysis);
        await db.SaveChangesAsync(token);

        var started = new TaskCompletionSource();
        if (!_running.TryAdd(targetId, started.Task))
        {
            db.ExternalAnalyses.Remove(analysis);
            await db.SaveChangesAsync(token);
            return OperationResult.Fail("Analiza tego celu już trwa.");
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await RunAsync(target, analysis.Id, lifetime.ApplicationStopping);
            }
            finally
            {
                _running.TryRemove(targetId, out _);
                started.TrySetResult();
            }
        });
        return OperationResult.Ok(analysis.Id);
    }

    /// <summary>Waits for a running analysis (tests and shutdown).</summary>
    public Task WaitAsync(int targetId) => _running.TryGetValue(targetId, out var task) ? task : Task.CompletedTask;

    /// <summary>Analyses left "running" by a previous process that was closed.</summary>
    public async Task MarkInterruptedAsync(CancellationToken token = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(token);
        await db.ExternalAnalyses.Where(a => a.Status == ExternalAnalysisStatus.Running)
            .ExecuteUpdateAsync(u => u.SetProperty(a => a.Status, ExternalAnalysisStatus.Failed).SetProperty(a => a.Error, "Analiza przerwana – aplikacja została zamknięta."), token);
    }

    private async Task RunAsync(ExternalTarget target, int analysisId, CancellationToken token)
    {
        string? error = null;
        ExternalSnapshot? snapshot = null;
        try
        {
            var sanNames = target.ScanTargetId is { } scopeId ? await CertificateNamesAsync(scopeId, target.Name, token) : [];
            snapshot = await CollectAsync(target, sanNames, token);
        }
        catch (OperationCanceledException)
        {
            error = "Analiza przerwana – aplikacja została zamknięta.";
        }
        catch (AnalysisFailedException ex)
        {
            error = ex.Message;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "External analysis {AnalysisId} failed", analysisId);
            error = $"Błąd analizy: {ex.Message}";
        }

        await using var db = await contextFactory.CreateDbContextAsync(CancellationToken.None);
        var analysis = await db.ExternalAnalyses.SingleAsync(a => a.Id == analysisId, CancellationToken.None);
        analysis.CompletedAt = timeProvider.GetUtcNow().UtcDateTime;
        if (snapshot is not null && error is null)
        {
            analysis.Status = ExternalAnalysisStatus.Completed;
            analysis.SnapshotJson = JsonSerializer.Serialize(snapshot, Json);
            analysis.HostCount = snapshot.Hosts.Count(h => h.Resolves);
            analysis.FindingCount = ExternalRules.Evaluate(snapshot).Count(f => f.Level > RiskLevel.Informational);
        }
        else
        {
            analysis.Status = ExternalAnalysisStatus.Failed;
            analysis.Error = error ?? "Brak odpowiedzi serwerów DNS.";
        }

        await db.SaveChangesAsync(CancellationToken.None);
        logger.LogInformation("External analysis {AnalysisId} finished: {Status}, {Hosts} hosts", analysisId, analysis.Status, analysis.HostCount);
    }

    /// <summary>Collects the passive snapshot. Only DNS queries to the system resolvers and (optionally) one CT search.</summary>
    internal async Task<ExternalSnapshot> CollectAsync(ExternalTarget target, IReadOnlyList<string> certificateNames, CancellationToken token)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var resolvers = dns.Servers.Select(s => s.ToString()).ToList();
        var records = new List<DnsRecordView>();
        var notes = new List<string>();

        if (target.Kind == ExternalTargetKind.Address)
        {
            var address = IPAddress.Parse(target.Name);
            var ptr = await dns.QueryAsync(ReverseName(address), DnsMessage.TypePtr, token);
            if (!ptr.Answered) throw new AnalysisFailedException("Brak odpowiedzi serwerów DNS.");
            records.AddRange(ptr.Records.Where(r => r.Type == DnsMessage.TypePtr).Select(r => new DnsRecordView(target.Name, "PTR", r.Target ?? "", r.Ttl)));
            if (records.Count == 0) notes.Add("Adres nie ma rekordu PTR (nazwy zwrotnej).");
            return new ExternalSnapshot(target.Name, now, resolvers, records,
                [new ExternalHostView(target.Name, [target.Name], null, true, false, false, ["użytkownik"])], [], false, null, [], 0, notes);
        }

        var domain = target.Name;
        var rootTypes = new[] { DnsMessage.TypeA, DnsMessage.TypeAaaa, DnsMessage.TypeMx, DnsMessage.TypeNs, DnsMessage.TypeTxt, DnsMessage.TypeCaa, DnsMessage.TypeSoa };
        var rootAnswers = await Task.WhenAll(rootTypes.Select(t => dns.QueryAsync(domain, t, token)).Append(dns.QueryAsync("_dmarc." + domain, DnsMessage.TypeTxt, token)));
        if (rootAnswers.All(a => !a.Answered)) throw new AnalysisFailedException("Brak odpowiedzi serwerów DNS.");
        if (rootAnswers[0].NameDoesNotExist) notes.Add($"Domena {domain} nie istnieje w DNS (NXDOMAIN).");

        for (var i = 0; i < rootAnswers.Length; i++)
        {
            var type = i < rootTypes.Length ? rootTypes[i] : DnsMessage.TypeTxt;
            var owner = i < rootTypes.Length ? domain : "_dmarc." + domain;
            records.AddRange(rootAnswers[i].Records.Where(r => r.Type == type && r.Name.Equals(owner, StringComparison.OrdinalIgnoreCase))
                .Select(r => new DnsRecordView(owner, DnsMessage.TypeName(type), Format(r), r.Ttl)));
        }

        records = records.DistinctBy(r => (r.Name, r.Type, r.Value)).ToList();

        // A random name that cannot exist: if it resolves, the zone has a wildcard and every name "exists".
        var probe = await dns.QueryAsync($"weles-{Guid.NewGuid():N}"[..20] + "." + domain, DnsMessage.TypeA, token);
        var wildcard = probe.Records.Where(r => r.Type == DnsMessage.TypeA && r.Address is not null).Select(r => r.Address!.ToString()).Distinct().ToList();

        // Candidate names – only from authorised sources: the domain's own records, CT logs, the user, certificates seen in active scans.
        var candidates = new Dictionary<string, SortedSet<string>>(StringComparer.OrdinalIgnoreCase);
        void Add(string? name, string source)
        {
            if (DomainNames.CleanHostName(name) is { } clean && DomainNames.IsWithin(clean, domain))
            {
                if (!candidates.TryGetValue(clean, out var set)) candidates[clean] = set = [];
                set.Add(source);
            }
        }

        Add(domain, "DNS");
        foreach (var r in records.Where(r => r.Type == "MX")) Add(r.Value.Split(' ').Last(), "MX");
        foreach (var r in records.Where(r => r.Type == "NS")) Add(r.Value, "NS");
        foreach (var name in (target.KnownHosts ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries)) Add(name, "użytkownik");
        foreach (var name in certificateNames) Add(name, "certyfikat TLS");

        var certificates = new List<CtCertificateView>();
        string? ctError = null;
        if (target.UseCertificateTransparency)
        {
            var result = await ct.SearchAsync(domain, token);
            ctError = result.Error;
            certificates = result.Certificates.OrderByDescending(c => c.NotBefore).ToList();
            foreach (var name in certificates.SelectMany(c => c.Names)) Add(name, "CT");
        }

        // The domain, names given by the user and mail/DNS servers first; then CT names, most recently certified first.
        var lastSeen = certificates.SelectMany(c => c.Names.Select(n => (n, c.NotBefore))).GroupBy(x => x.n).ToDictionary(g => g.Key, g => g.Max(x => x.NotBefore));
        var ordered = candidates.OrderBy(c => c.Value.Contains("CT") && c.Value.Count == 1 ? 1 : 0)
            .ThenByDescending(c => lastSeen.GetValueOrDefault(c.Key))
            .ThenBy(c => c.Key, StringComparer.Ordinal).ToList();
        var selected = ordered.Take(options.Value.MaxHosts).ToList();
        var skipped = ordered.Count - selected.Count;
        if (skipped > 0) notes.Add($"Sprawdzono {selected.Count} z {ordered.Count} nazw (limit analizy); pominięto najstarsze nazwy z CT.");

        var hosts = new ConcurrentBag<ExternalHostView>();
        await Parallel.ForEachAsync(selected, new ParallelOptions { MaxDegreeOfParallelism = options.Value.DnsConcurrency, CancellationToken = token }, async (entry, t) =>
        {
            var a = await dns.QueryAsync(entry.Key, DnsMessage.TypeA, t);
            var aaaa = await dns.QueryAsync(entry.Key, DnsMessage.TypeAaaa, t);
            var addresses = a.Records.Concat(aaaa.Records).Where(r => r.Type is DnsMessage.TypeA or DnsMessage.TypeAaaa && r.Address is not null)
                .Select(r => r.Address!.ToString()).Distinct().ToList();
            var cname = LastCname(entry.Key, a.Records);
            var dangling = cname is not null && addresses.Count == 0 && a.NameDoesNotExist;
            var matchesWildcard = wildcard.Count > 0 && addresses.Count > 0 && addresses.All(wildcard.Contains) && !entry.Value.Overlaps(["DNS", "MX", "NS", "użytkownik"]);
            hosts.Add(new ExternalHostView(entry.Key, addresses, cname, addresses.Count > 0, dangling, matchesWildcard, entry.Value.ToList()));
        });

        return new ExternalSnapshot(domain, now, resolvers, records,
            hosts.OrderBy(h => h.Name == domain ? 0 : 1).ThenBy(h => string.Join('.', h.Name.Split('.').Reverse()), StringComparer.Ordinal).ToList(),
            certificates.Take(200).ToList(), target.UseCertificateTransparency, ctError, wildcard, skipped, notes);
    }

    public async Task<IReadOnlyList<ExternalAnalysisRef>> AnalysesAsync(int targetId, CancellationToken token = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(token);
        return await db.ExternalAnalyses.AsNoTracking().Where(a => a.ExternalTargetId == targetId).OrderByDescending(a => a.Id).Take(20)
            .Select(a => new ExternalAnalysisRef(a.Id, a.Status, a.StartedAt, a.CompletedAt, a.HostCount, a.FindingCount, a.Error))
            .ToListAsync(token);
    }

    /// <summary>The latest completed analysis (or the given one) with its findings re-evaluated by the current rules.</summary>
    public async Task<ExternalAnalysisView?> AnalysisAsync(int targetId, int? analysisId = null, CancellationToken token = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(token);
        var query = db.ExternalAnalyses.AsNoTracking().Where(a => a.ExternalTargetId == targetId);
        var row = analysisId is { } id
            ? await query.SingleOrDefaultAsync(a => a.Id == id, token)
            : await query.OrderByDescending(a => a.Status == ExternalAnalysisStatus.Completed).ThenByDescending(a => a.Id).FirstOrDefaultAsync(token);
        if (row is null) return null;
        var snapshot = row.SnapshotJson is null ? null : JsonSerializer.Deserialize<ExternalSnapshot>(row.SnapshotJson, Json);
        return new ExternalAnalysisView(new ExternalAnalysisRef(row.Id, row.Status, row.StartedAt, row.CompletedAt, row.HostCount, row.FindingCount, row.Error),
            snapshot, snapshot is null ? [] : ExternalRules.Evaluate(snapshot));
    }

    /// <summary>
    /// Creates (or replaces the entries of) the active-scan scope for hosts the user selected from the passive analysis.
    /// The scope is NOT approved: the user approves it in Network Discovery, confirming permission again.
    /// </summary>
    public async Task<OperationResult> PrepareActiveScopeAsync(int targetId, IReadOnlyCollection<string> hosts, CancellationToken token = default)
    {
        var view = await AnalysisAsync(targetId, null, token);
        await using var db = await contextFactory.CreateDbContextAsync(token);
        var target = await db.ExternalTargets.SingleOrDefaultAsync(t => t.Id == targetId, token);
        if (target is null) return OperationResult.Fail("Cel nie istnieje.");
        if (hosts.Count == 0) return OperationResult.Fail("Wybierz co najmniej jeden host.");
        if (view?.Snapshot is null) return OperationResult.Fail("Najpierw wykonaj analizę pasywną.");

        var allowed = view.Snapshot.Hosts.Where(h => h.Resolves && h.Addresses.Any(a => IPAddress.TryParse(a, out var ip) && AddressClassifier.IsPublic(ip)))
            .Select(h => h.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var unknown = hosts.Where(h => !allowed.Contains(h)).ToList();
        if (unknown.Count > 0) return OperationResult.Fail($"Te nazwy nie wskazują na adres publiczny w ostatniej analizie: {string.Join(", ", unknown)}");

        var input = new ScanTargetInput($"Zewnętrzny: {target.Name}",
            "Utworzony w module Powierzchnia ataku z hostów wybranych w analizie pasywnej. Skan obejmuje adresy publiczne.",
            string.Join('\n', hosts.Order(StringComparer.Ordinal)), null, AllowPublicAddresses: true);
        var existing = target.ScanTargetId is { } scopeId && await db.ScanTargets.AnyAsync(s => s.Id == scopeId, token) ? scopeId : (int?)null;
        var result = existing is { } id ? await scopes.UpdateAsync(id, input, token) : await scopes.CreateAsync(input, token);
        if (!result.Success) return result;

        target.ScanTargetId = result.Id;
        await db.ScanTargets.Where(t => t.Id == result.Id).ExecuteUpdateAsync(u => u.SetProperty(t => t.IsExternal, true), token);
        await db.SaveChangesAsync(token);
        logger.LogInformation("Active scope {ScopeId} prepared for external target {TargetId} with {Count} hosts (awaiting approval)", result.Id, targetId, hosts.Count);
        return result;
    }

    /// <summary>Results of the latest scan of the target's active scope: public services, certificates and findings.</summary>
    public async Task<ExternalActiveResult?> ActiveResultAsync(int targetId, CancellationToken token = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(token);
        var scopeId = await db.ExternalTargets.Where(t => t.Id == targetId).Select(t => t.ScanTargetId).SingleOrDefaultAsync(token);
        if (scopeId is null) return null;
        var scan = await db.Scans.AsNoTracking().Where(s => s.ScanTargetId == scopeId && s.CompletedAt != null)
            .OrderByDescending(s => s.Id).FirstOrDefaultAsync(token);
        if (scan is null) return null;

        var hosts = await db.DiscoveredHosts.AsNoTracking().Where(h => h.ScanId == scan.Id)
            .Include(h => h.Ports).ThenInclude(p => p.Service).ThenInclude(s => s!.Certificates)
            .ToListAsync(token);
        var findings = await db.RiskFindings.AsNoTracking().Where(f => f.ScanId == scan.Id)
            .Select(f => new { f.AssetId, f.Title, f.Level, f.Score, f.Evidence, f.Port }).ToListAsync(token);

        var result = hosts.OrderBy(h => h.Hostname ?? h.IpAddress, StringComparer.Ordinal).Select(h => new ExternalActiveHost(h.AssetId, h.IpAddress, h.Hostname,
            h.Ports.Where(p => p.State == PortState.Open).OrderBy(p => p.Port).Select(p =>
            {
                var cert = p.Service?.Certificates.OrderByDescending(c => c.NotAfter).FirstOrDefault();
                return new ExternalServiceView(p.Port, p.Service?.ServiceName, p.Service?.Product, p.Service?.Version, p.Service?.IsTls ?? false,
                    ExternalRules.IsAdministrativePort(p.Port), cert?.Subject, cert?.NotAfter, cert?.IsSelfSigned ?? false, cert?.HostnameMatches);
            }).ToList(),
            findings.Where(f => f.AssetId == h.AssetId).OrderByDescending(f => f.Score).Select(f => new ExternalRiskView(f.Title, f.Level, f.Score, f.Evidence, f.Port)).ToList()))
            .ToList();
        return new ExternalActiveResult(scan.Id, scan.CompletedAt ?? scan.CreatedAt, scan.Status, scan.PortSpecification, scan.HostsTargeted, result);
    }

    /// <summary>Names from certificates seen by active scans of the scope – another authorised source of subdomains.</summary>
    private async Task<IReadOnlyList<string>> CertificateNamesAsync(int scopeId, string domain, CancellationToken token)
    {
        await using var db = await contextFactory.CreateDbContextAsync(token);
        var sans = await db.Certificates.AsNoTracking()
            .Where(c => c.Service!.Port!.Host!.Scan!.ScanTargetId == scopeId && c.SubjectAlternativeNames != null)
            .Select(c => c.SubjectAlternativeNames!).Distinct().OrderBy(s => s).Take(500).ToListAsync(token);
        return sans.SelectMany(s => s.Split([',', ';', '\n', ' '], StringSplitOptions.RemoveEmptyEntries))
            .Select(n => n.Replace("DNS:", "", StringComparison.OrdinalIgnoreCase))
            .Select(DomainNames.CleanHostName).OfType<string>().Where(n => DomainNames.IsWithin(n, domain)).Distinct().ToList();
    }

    private static (List<string> Hosts, List<string> Errors) ParseKnownHosts(string? text, string root, ExternalTargetKind kind)
    {
        var hosts = new List<string>();
        var errors = new List<string>();
        foreach (var raw in (text ?? "").Split(['\n', ',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (kind == ExternalTargetKind.Address)
            {
                errors.Add("Dodatkowe nazwy hostów można podać tylko dla domeny.");
                break;
            }

            var name = DomainNames.CleanHostName(raw);
            if (name is null || !DomainNames.IsWithin(name, root)) errors.Add($"{raw} nie jest nazwą w domenie {root}.");
            else hosts.Add(name);
        }

        if (hosts.Count > 200) errors.Add("Można podać maksymalnie 200 nazw.");
        return (hosts.Distinct().ToList(), errors);
    }

    private static string? LastCname(string name, IReadOnlyList<DnsRecord> records)
    {
        string? target = null;
        var current = name;
        for (var i = 0; i < 10; i++)
        {
            var next = records.FirstOrDefault(r => r.Type == DnsMessage.TypeCname && r.Name.Equals(current, StringComparison.OrdinalIgnoreCase))?.Target;
            if (next is null) break;
            target = current = next;
        }

        return target;
    }

    private static string Format(DnsRecord r) => r.Type switch
    {
        DnsMessage.TypeA or DnsMessage.TypeAaaa => r.Address?.ToString() ?? "",
        DnsMessage.TypeMx => $"{r.Preference} {r.Target}",
        DnsMessage.TypeTxt => string.Concat(r.Texts ?? []),
        DnsMessage.TypeCaa => r.Texts is [var tag, var value] ? $"{r.Preference} {tag} \"{value}\"" : "",
        _ => r.Target ?? ""
    };

    private static string ReverseName(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? string.Join('.', bytes.Reverse()) + ".in-addr.arpa"
            : string.Join('.', bytes.Reverse().SelectMany(b => new[] { (b & 0xF).ToString("x"), (b >> 4).ToString("x") })) + ".ip6.arpa";
    }
}

/// <summary>An expected failure with a message for the user (e.g. DNS servers did not answer).</summary>
internal sealed class AnalysisFailedException(string message) : Exception(message);

/// <summary>Marks analyses interrupted by the previous shutdown.</summary>
public sealed class ExternalStartupService(ExternalSurfaceService service) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) => service.MarkInterruptedAsync(cancellationToken);
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
