using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Scanning;

namespace Weles.Infrastructure.Agents;

public sealed record AgentScopeView(int Id, string Name, bool IsApproved);

/// <param name="IsOnline">The agent called within the last few poll intervals.</param>
public sealed record AgentView(int Id, string Name, AgentStatus Status, bool IsOnline, DateTime CreatedAt, DateTime? EnrollmentExpiresAt, DateTime? EnrolledAt,
    DateTime? LastSeenAt, string? LastAddress, string? Hostname, string? OperatingSystem, string? AgentVersion, AgentSystemInfo? System, DateTime? RevokedAt,
    IReadOnlyList<AgentScopeView> Scopes, int Scans, int? ActiveScanId);

/// <summary>The one-time enrollment code – shown to the user once, never stored in plain text.</summary>
public sealed record AgentEnrollment(AgentView Agent, string Code);

/// <summary>Outcome of an agent protocol call: an HTTP status and the body or the reason.</summary>
public sealed record AgentCallResult<T>(int StatusCode, T? Body, string? Error = null) where T : class
{
    public static AgentCallResult<T> Ok(T body) => new(200, body);
    public static AgentCallResult<T> Fail(int status, string error) => new(status, null, error);
}

/// <summary>
/// Remote agents: management from the panel (create with a one-time code, assign scopes, start scans, revoke) and the
/// server side of <see cref="AgentProtocol"/>. Everything an agent sends is untrusted: hosts outside the scan's scope
/// are dropped, sizes and texts are bounded, and an agent can touch only its own scans.
/// </summary>
public sealed partial class AgentService(
    IDbContextFactory<WelesDbContext> contextFactory,
    ScanResultWriter writer,
    ScanCoordinator coordinator,
    ScanPostProcessor postProcessor,
    OuiDatabase oui,
    IOptions<ScanOptions> scanOptions,
    TimeProvider time,
    ILogger<AgentService> logger)
{
    public static readonly TimeSpan EnrollmentValidity = TimeSpan.FromHours(24);
    public static readonly TimeSpan OnlineWindow = TimeSpan.FromSeconds(AgentProtocol.PollSeconds * 3 + 15);

    /// <summary>A running agent scan with no call from its agent for this long is marked failed.</summary>
    public static readonly TimeSpan SilentScanTimeout = TimeSpan.FromMinutes(10);

    private const int MaxFailuresPerWindow = 10;
    private static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(10);

    private readonly ConcurrentDictionary<string, (int Count, DateTime Since)> _failures = new();
    private readonly ConcurrentDictionary<int, HashSet<IPAddress>> _scopeOfScan = new();

    private DateTime Now => time.GetUtcNow().UtcDateTime;

    // ---------------------------------------------------------------- panel

    public async Task<IReadOnlyList<AgentView>> ListAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var agents = await db.Agents.AsNoTracking().Include(a => a.Scopes).ThenInclude(s => s.ScanTarget).OrderBy(a => a.Name).ToListAsync(ct);
        var ids = agents.Select(a => a.Id).ToList();
        var scans = await db.Scans.AsNoTracking().Where(s => s.AgentId != null && ids.Contains(s.AgentId.Value))
            .Select(s => new { AgentId = s.AgentId!.Value, s.Id, s.Status }).ToListAsync(ct);
        return agents.Select(a => View(a, scans.Count(s => s.AgentId == a.Id),
            scans.Where(s => s.AgentId == a.Id && s.Status is ScanStatus.Pending or ScanStatus.Running).Select(s => (int?)s.Id).Max())).ToList();
    }

    /// <summary>Scopes an agent may get: approved or not, but local only – no public addresses, no domain names.</summary>
    public async Task<IReadOnlyList<AgentScopeView>> EligibleScopesAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var targets = await db.ScanTargets.AsNoTracking().Include(t => t.Entries).Where(t => !t.IsExternal && !t.AllowPublicAddresses).OrderBy(t => t.Name).ToListAsync(ct);
        return targets.Where(t => t.Entries.Count > 0 && t.Entries.All(e => e.Kind != ScanTargetEntryKind.Domain))
            .Select(t => new AgentScopeView(t.Id, t.Name, t.IsApproved)).ToList();
    }

    public async Task<(AgentEnrollment? Enrollment, string? Error)> CreateAsync(string name, IReadOnlyCollection<int> scopeIds, CancellationToken ct = default)
    {
        name = name.Trim();
        if (name.Length is 0 or > 100) return (null, "Nazwa agenta musi mieć od 1 do 100 znaków.");
        if (await ScopeErrorAsync(scopeIds, ct) is { } scopeError) return (null, scopeError);

        await using var db = await contextFactory.CreateDbContextAsync(ct);
        if (await db.Agents.AnyAsync(a => a.Name == name, ct)) return (null, "Agent o tej nazwie już istnieje.");
        var code = NewSecret();
        var agent = new Agent
        {
            Name = name, Status = AgentStatus.Pending, CreatedAt = Now, EnrollmentCodeHash = Hash(code), EnrollmentExpiresAt = Now + EnrollmentValidity,
            Scopes = scopeIds.Distinct().Select(id => new AgentScope { ScanTargetId = id }).ToList()
        };
        db.Agents.Add(agent);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Agent #{Id} created ({Scopes} scopes), waiting for enrollment", agent.Id, agent.Scopes.Count);
        return (new AgentEnrollment((await ListAsync(ct)).First(a => a.Id == agent.Id), code), null);
    }

    /// <summary>A new one-time code for an agent that has not enrolled yet (the previous code stops working).</summary>
    public async Task<string?> RenewCodeAsync(int agentId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var agent = await db.Agents.SingleOrDefaultAsync(a => a.Id == agentId && a.Status == AgentStatus.Pending, ct);
        if (agent is null) return null;
        var code = NewSecret();
        agent.EnrollmentCodeHash = Hash(code);
        agent.EnrollmentExpiresAt = Now + EnrollmentValidity;
        await db.SaveChangesAsync(ct);
        logger.LogInformation("New enrollment code issued for agent #{Id}", agentId);
        return code;
    }

    public async Task<string?> SetScopesAsync(int agentId, IReadOnlyCollection<int> scopeIds, CancellationToken ct = default)
    {
        if (await ScopeErrorAsync(scopeIds, ct) is { } error) return error;
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var agent = await db.Agents.Include(a => a.Scopes).SingleOrDefaultAsync(a => a.Id == agentId && a.Status != AgentStatus.Revoked, ct);
        if (agent is null) return "Agent nie istnieje lub został unieważniony.";
        agent.Scopes.RemoveAll(s => !scopeIds.Contains(s.ScanTargetId));
        foreach (var id in scopeIds.Distinct().Where(id => agent.Scopes.All(s => s.ScanTargetId != id))) agent.Scopes.Add(new AgentScope { ScanTargetId = id });
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Scopes of agent #{Id} changed ({Count})", agentId, agent.Scopes.Count);
        return null;
    }

    /// <summary>Revokes at once: the token stops working, queued and running scans of the agent are cancelled.</summary>
    public async Task<bool> RevokeAsync(int agentId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var agent = await db.Agents.SingleOrDefaultAsync(a => a.Id == agentId && a.Status != AgentStatus.Revoked, ct);
        if (agent is null) return false;
        agent.Status = AgentStatus.Revoked;
        agent.TokenHash = null;
        agent.EnrollmentCodeHash = null;
        agent.RevokedAt = Now;
        await db.SaveChangesAsync(ct);
        foreach (var scan in await db.Scans.Where(s => s.AgentId == agentId && (s.Status == ScanStatus.Pending || s.Status == ScanStatus.Running)).ToListAsync(ct))
        {
            await FinishScanAsync(db, scan, ScanStatus.Cancelled, "Skan anulowany – dostęp agenta został unieważniony.", ct);
        }

        logger.LogWarning("Agent #{Id} revoked", agentId);
        return true;
    }

    /// <summary>Only a revoked or never enrolled agent can be deleted; its scans stay in the history.</summary>
    public async Task<bool> DeleteAsync(int agentId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var agent = await db.Agents.SingleOrDefaultAsync(a => a.Id == agentId && a.Status != AgentStatus.Active, ct);
        if (agent is null) return false;
        db.Agents.Remove(agent);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Agent #{Id} deleted", agentId);
        return true;
    }

    /// <summary>Queues a scan for the agent; it picks it up with its next heartbeat.</summary>
    public async Task<OperationResult> StartScanAsync(int agentId, int scopeId, string portSpecification, CancellationToken ct = default)
    {
        if (!PortSpecification.TryParse(portSpecification, out _, out var portError)) return OperationResult.Fail(portError!);
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var agent = await db.Agents.Include(a => a.Scopes).SingleOrDefaultAsync(a => a.Id == agentId, ct);
        if (agent is not { Status: AgentStatus.Active }) return OperationResult.Fail("Agent nie jest aktywny.");
        if (agent.Scopes.All(s => s.ScanTargetId != scopeId)) return OperationResult.Fail("Ten zakres nie jest przypisany do agenta.");
        var target = await db.ScanTargets.Include(t => t.Entries).SingleOrDefaultAsync(t => t.Id == scopeId, ct);
        if (target is null) return OperationResult.Fail("Zakres nie istnieje.");
        if (!target.IsApproved) return OperationResult.Fail("Zakres nie jest zatwierdzony. Zatwierdź go przed uruchomieniem skanu.");
        if (ScopeProblem(target) is { } problem) return OperationResult.Fail(problem);
        if (await db.Scans.AnyAsync(s => s.ScanTargetId == scopeId && (s.Status == ScanStatus.Pending || s.Status == ScanStatus.Running), ct))
            return OperationResult.Fail("Dla tego zakresu trwa już skan.");
        if (await db.Scans.AnyAsync(s => s.AgentId == agentId && (s.Status == ScanStatus.Pending || s.Status == ScanStatus.Running), ct))
            return OperationResult.Fail("Agent ma już skan w kolejce lub w toku.");

        var scan = new Scan
        {
            ScanTargetId = scopeId, AgentId = agentId, Status = ScanStatus.Pending, Trigger = ScanTrigger.Agent,
            PortSpecification = portSpecification.Trim().ToLowerInvariant(), CreatedAt = Now,
            // The scope as approved now – later edits of the scope do not change what this agent may scan.
            ScopeSnapshot = JsonSerializer.Serialize(target.Entries.Select(e => new { e.Value, e.IsExclusion }))
        };
        db.Scans.Add(scan);
        await db.SaveChangesAsync(ct);
        coordinator.Track(scan.Id);
        await writer.AddEventAsync(scan.Id, ScanEventLevel.Info, $"Skan zlecony agentowi „{agent.Name}” – rozpocznie się przy jego najbliższym połączeniu.");
        logger.LogInformation("Scan {ScanId} queued for agent #{AgentId} (scope {ScopeId})", scan.Id, agentId, scopeId);
        return OperationResult.Ok(scan.Id);
    }

    /// <summary>Fails agent scans whose agent went silent, so nothing stays "running" forever.</summary>
    public async Task<int> FailSilentScansAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var limit = Now - SilentScanTimeout;
        var stale = await db.Scans.Include(s => s.Agent)
            .Where(s => s.Trigger == ScanTrigger.Agent && s.Status == ScanStatus.Running)
            .ToListAsync(ct);
        stale = stale.Where(s => s.Agent?.LastSeenAt is not { } seen || seen < limit).ToList();
        foreach (var scan in stale)
        {
            await FinishScanAsync(db, scan, ScanStatus.Failed, "Agent przestał się łączyć w trakcie skanu – zachowano przesłane wyniki.", ct);
        }

        return stale.Count;
    }

    // ---------------------------------------------------------------- protocol

    public async Task<AgentCallResult<EnrollResponse>> EnrollAsync(EnrollRequest request, string remote, CancellationToken ct = default)
    {
        if (IsThrottled(remote)) return AgentCallResult<EnrollResponse>.Fail(429, "Zbyt wiele nieudanych prób – spróbuj później.");
        if (string.IsNullOrWhiteSpace(request.Code) || request.Code.Length > 100 || request.System is null)
        {
            Failed(remote);
            return AgentCallResult<EnrollResponse>.Fail(400, "Nieprawidłowe żądanie rejestracji.");
        }

        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var hash = Hash(request.Code.Trim());
        var agent = await db.Agents.SingleOrDefaultAsync(a => a.EnrollmentCodeHash == hash && a.Status == AgentStatus.Pending, ct);
        if (agent is null || agent.EnrollmentExpiresAt < Now)
        {
            Failed(remote);
            logger.LogWarning("Agent enrollment refused from {Remote}: {Reason}", remote, agent is null ? "unknown code" : "expired code");
            return AgentCallResult<EnrollResponse>.Fail(401, agent is null ? "Nieznany lub już użyty kod rejestracji." : "Kod rejestracji wygasł – wygeneruj nowy w WELES.");
        }

        var token = NewSecret();
        agent.Status = AgentStatus.Active;
        agent.TokenHash = Hash(token);
        agent.EnrollmentCodeHash = null;
        agent.EnrollmentExpiresAt = null;
        agent.EnrolledAt = Now;
        Seen(agent, request.System, remote);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Agent #{Id} enrolled from {Remote} ({Host})", agent.Id, remote, agent.Hostname);
        return AgentCallResult<EnrollResponse>.Ok(new EnrollResponse(agent.Id, agent.Name, token));
    }

    /// <summary>The active agent holding this token, or null. Repeated failures from one address are throttled.</summary>
    public async Task<(Agent? Agent, int Status)> AuthenticateAsync(string? token, string remote, CancellationToken ct = default)
    {
        if (IsThrottled(remote)) return (null, 429);
        if (string.IsNullOrEmpty(token) || token.Length > 100)
        {
            Failed(remote);
            return (null, 401);
        }

        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var hash = Hash(token);
        var agent = await db.Agents.AsNoTracking().Include(a => a.Scopes).SingleOrDefaultAsync(a => a.TokenHash == hash, ct);
        if (agent is not { Status: AgentStatus.Active })
        {
            Failed(remote);
            logger.LogWarning("Agent call with an invalid or revoked token from {Remote}", remote);
            return (null, 401);
        }

        return (agent, 200);
    }

    public async Task<AgentCallResult<HeartbeatResponse>> HeartbeatAsync(Agent agent, HeartbeatRequest request, string remote, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var tracked = await db.Agents.SingleAsync(a => a.Id == agent.Id, ct);
        if (request.System is not null) Seen(tracked, request.System, remote);
        else tracked.LastSeenAt = Now;
        await db.SaveChangesAsync(ct);

        var active = await db.Scans.Include(s => s.ScanTarget)
            .Where(s => s.AgentId == agent.Id && (s.Status == ScanStatus.Pending || s.Status == ScanStatus.Running))
            .OrderBy(s => s.Id).ToListAsync(ct);
        var running = active.FirstOrDefault(s => s.Status == ScanStatus.Running);

        // The agent works on a scan WELES no longer expects (stopped, failed after a timeout) – tell it to stop.
        if (request.RunningScanId is { } reported)
        {
            var cancel = running?.Id != reported || coordinator.IsStopRequested(reported);
            return AgentCallResult<HeartbeatResponse>.Ok(new HeartbeatResponse(agent.Name, AgentProtocol.PollSeconds, null, cancel));
        }

        if (running is not null)
        {
            // The agent is idle but WELES thinks it is scanning – it was restarted mid-scan.
            await FinishScanAsync(db, running, ScanStatus.Failed, "Agent został ponownie uruchomiony w trakcie skanu – zachowano przesłane wyniki.", ct);
        }

        var pending = active.FirstOrDefault(s => s.Status == ScanStatus.Pending);
        if (pending is null) return AgentCallResult<HeartbeatResponse>.Ok(new HeartbeatResponse(agent.Name, AgentProtocol.PollSeconds, null, false));
        if (coordinator.IsStopRequested(pending.Id))
        {
            await FinishScanAsync(db, pending, ScanStatus.Cancelled, "Skan zatrzymany przed rozpoczęciem.", ct);
            return AgentCallResult<HeartbeatResponse>.Ok(new HeartbeatResponse(agent.Name, AgentProtocol.PollSeconds, null, false));
        }

        // The scope may have been unassigned or its approval withdrawn since the scan was queued.
        if (agent.Scopes.All(s => s.ScanTargetId != pending.ScanTargetId) || pending.ScanTarget is not { IsApproved: true })
        {
            await FinishScanAsync(db, pending, ScanStatus.Cancelled, "Skan anulowany – zakres nie jest już zatwierdzony lub przypisany do agenta.", ct);
            return AgentCallResult<HeartbeatResponse>.Ok(new HeartbeatResponse(agent.Name, AgentProtocol.PollSeconds, null, false));
        }

        var entries = Snapshot(pending.ScopeSnapshot);
        pending.Status = ScanStatus.Running;
        pending.StartedAt = Now;
        await db.SaveChangesAsync(ct);
        var (_, progress) = coordinator.Begin(pending.Id, CancellationToken.None);
        progress.Phase = ScanPhase.HostDiscovery;
        progress.Activity = $"Agent „{agent.Name}” skanuje";
        await writer.AddEventAsync(pending.Id, ScanEventLevel.Info, $"Rozpoczęto skan zakresu „{pending.ScanTarget!.Name}” przez agenta „{agent.Name}” (porty: {pending.PortSpecification}).");
        logger.LogInformation("Scan {ScanId} handed to agent #{AgentId}", pending.Id, agent.Id);
        return AgentCallResult<HeartbeatResponse>.Ok(new HeartbeatResponse(agent.Name, AgentProtocol.PollSeconds,
            new AgentJob(pending.Id, pending.ScanTarget.Name, entries, pending.PortSpecification), false));
    }

    public async Task<AgentCallResult<ResultsResponse>> ResultsAsync(Agent agent, int scanId, ResultsRequest request, string remote, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var scan = await db.Scans.SingleOrDefaultAsync(s => s.Id == scanId && s.AgentId == agent.Id, ct);
        if (scan is null) return AgentCallResult<ResultsResponse>.Fail(404, "Nieznany skan.");
        if (scan.Status != ScanStatus.Running) return AgentCallResult<ResultsResponse>.Ok(new ResultsResponse(0, request.Hosts?.Count ?? 0, true));
        if (request.Hosts is null || request.Events is null || request.State is null) return AgentCallResult<ResultsResponse>.Fail(400, "Niekompletne żądanie.");
        if (request.Hosts.Count > AgentProtocol.MaxHostsPerUpload || request.Events.Count > AgentProtocol.MaxEventsPerUpload)
            return AgentCallResult<ResultsResponse>.Fail(413, "Za dużo danych w jednym żądaniu.");

        await TouchAsync(db, agent.Id, remote, ct);
        var scope = await ScopeOfScanAsync(scan, ct);
        await ApplyStateAsync(db, scan, request.State, scope.Count, ct);
        foreach (var e in request.Events) await AddAgentEventAsync(scan.Id, e);

        var progress = ProgressOf(scan.Id);
        var agentMacs = MacsOf(agent);
        var known = (await db.DiscoveredHosts.AsNoTracking().Where(h => h.ScanId == scanId).Select(h => h.IpAddress).ToListAsync(ct)).ToHashSet();
        int accepted = 0, rejected = 0;
        foreach (var host in request.Hosts)
        {
            var result = ToHostResult(host, scope, agentMacs);
            if (result is null || !known.Add(result.Address.ToString()))
            {
                rejected++;
                continue;
            }

            await writer.SaveHostAsync(scan.Id, result);
            progress.HostProbed(true);
            progress.HostCompleted();
            accepted++;
        }

        progress.Phase = ScanPhase.PortScan;
        progress.Activity = $"Agent „{agent.Name}”: przesłano {known.Count} hostów";
        if (rejected > 0)
        {
            logger.LogWarning("Agent #{AgentId} sent {Count} host(s) outside scope or invalid for scan {ScanId}", agent.Id, rejected, scanId);
            await writer.AddEventAsync(scan.Id, ScanEventLevel.Warning, $"Odrzucono {rejected} wyników agenta (adres spoza zakresu, duplikat lub nieprawidłowe dane).");
        }

        return AgentCallResult<ResultsResponse>.Ok(new ResultsResponse(accepted, rejected, coordinator.IsStopRequested(scanId)));
    }

    public async Task<AgentCallResult<ResultsResponse>> CompleteAsync(Agent agent, int scanId, CompleteRequest request, string remote, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var scan = await db.Scans.SingleOrDefaultAsync(s => s.Id == scanId && s.AgentId == agent.Id, ct);
        if (scan is null) return AgentCallResult<ResultsResponse>.Fail(404, "Nieznany skan.");
        if (scan.Status != ScanStatus.Running) return AgentCallResult<ResultsResponse>.Ok(new ResultsResponse(0, 0, false));
        if (request.State is null || request.Events is null || request.Events.Count > AgentProtocol.MaxEventsPerUpload
            || request.Status is not (ScanStatus.Completed or ScanStatus.Failed or ScanStatus.Cancelled))
            return AgentCallResult<ResultsResponse>.Fail(400, "Nieprawidłowe zakończenie skanu.");

        await TouchAsync(db, agent.Id, remote, ct);
        var scope = await ScopeOfScanAsync(scan, ct);
        await ApplyStateAsync(db, scan, request.State, scope.Count, ct);
        foreach (var e in request.Events) await AddAgentEventAsync(scan.Id, e);

        var message = request.Status switch
        {
            ScanStatus.Completed => $"Skan agenta zakończony: {scan.HostsAlive} hostów, {scan.OpenPorts} otwartych portów.",
            ScanStatus.Cancelled => "Skan agenta zatrzymany. Zachowano przesłane wyniki.",
            _ => "Błąd skanowania po stronie agenta: " + Clean(request.Error ?? "nieznany błąd", 500)
        };
        await FinishScanAsync(db, scan, request.Status, message, ct);
        if (request.Status != ScanStatus.Failed || scan.HostsAlive > 0) await postProcessor.RunAsync(scan.Id, ct);
        return AgentCallResult<ResultsResponse>.Ok(new ResultsResponse(0, 0, false));
    }

    // ---------------------------------------------------------------- validation of agent data

    /// <summary>
    /// Turns what the agent sent into a scan result – or null when the host is not in the scan's scope or the data is
    /// malformed. Texts are bounded, the vendor is looked up here (not taken from the agent).
    /// </summary>
    internal HostScanResult? ToHostResult(AgentHost host, IReadOnlySet<IPAddress> scope, IReadOnlySet<string> agentMacs)
    {
        if (host is null || !IPAddress.TryParse(host.Address, out var address)) return null;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (!scope.Contains(address) || host.Classification is null || host.OpenPorts is null) return null;
        if (!Enum.IsDefined(host.Classification.Type)) return null;
        if (host.OpenPorts.Count > 1100 || host.OpenPorts.Select(p => p?.Port).Distinct().Count() != host.OpenPorts.Count) return null;

        var ports = new List<PortScanResult>();
        foreach (var p in host.OpenPorts)
        {
            if (p is null || p.Port is < 1 or > 65535) return null;
            ports.Add(new PortScanResult(p.Port, Clean(p.Reason, 32), p.Service is null ? null : CleanProbe(p.Service)));
        }

        var mac = host.MacAddress is { } m && MacPattern().IsMatch(m) ? m.ToLowerInvariant() : null;
        var classification = new HostClassification(host.Classification.Type, CleanOrNull(host.Classification.OsFamily, 64),
            Math.Clamp(host.Classification.Confidence, 0, 100), (host.Classification.Reasons ?? []).Take(20).Select(r => Clean(r, 300)).ToList());
        var announced = host.AnnouncedServices?.Where(s => s is not null).Take(30)
            .Select(s => new MdnsService(Clean(s.Type, 100), Clean(s.Instance, 200), s.Port is >= 1 and <= 65535 ? s.Port : null, (s.Txt ?? []).Take(16).Select(t => Clean(t, 200)).ToList()))
            .ToList();
        var methods = host.Methods & (DiscoveryMethod.Icmp | DiscoveryMethod.TcpConnect | DiscoveryMethod.Arp | DiscoveryMethod.Dns | DiscoveryMethod.Mdns) | DiscoveryMethod.Agent;
        return new HostScanResult(address, methods, host.RoundTripMs is >= 0 and < 60_000 ? host.RoundTripMs : null, host.Ttl is >= 0 and <= 255 ? host.Ttl : null,
            CleanOrNull(host.Hostname, 255), mac, oui.Lookup(mac), host.IsGateway, classification, ports, announced,
            host.IsAgentMachine && agentMacs.Count > 0 ? agentMacs : null);
    }

    private static ServiceProbeResult CleanProbe(ServiceProbeResult probe)
    {
        var id = probe.Identification;
        var identification = id is null ? Core.Models.ServiceIdentification.FromPortOnly(0) with { ServiceName = "unknown" } : new Core.Models.ServiceIdentification
        {
            ServiceName = Clean(id.ServiceName, 64), Product = CleanOrNull(id.Product, 128), Vendor = CleanOrNull(id.Vendor, 128), Version = CleanOrNull(id.Version, 128),
            Cpe = CleanOrNull(id.Cpe, 256), Banner = CleanOrNull(id.Banner, 1024, keepLines: true), DistributionHint = CleanOrNull(id.DistributionHint, 128),
            OsHint = CleanOrNull(id.OsHint, 64), Confidence = Math.Clamp(id.Confidence, 0, 100), Method = Clean(id.Method, 64), IsTls = id.IsTls,
            Extra = (id.Extra ?? []).Take(40).ToDictionary(e => Clean(e.Key, 64), e => Clean(e.Value, 1024))
        };
        var c = probe.Certificate;
        var certificate = c is null ? null : c with
        {
            Subject = Clean(c.Subject, 1024), Issuer = Clean(c.Issuer, 1024), Thumbprint = Clean(c.Thumbprint, 128), SerialNumber = CleanOrNull(c.SerialNumber, 128),
            SubjectAlternativeNames = (c.SubjectAlternativeNames ?? []).Take(100).Select(s => Clean(s, 255)).ToList(), KeyAlgorithm = CleanOrNull(c.KeyAlgorithm, 64),
            SignatureAlgorithm = CleanOrNull(c.SignatureAlgorithm, 64), TlsProtocol = CleanOrNull(c.TlsProtocol, 32), CipherSuite = CleanOrNull(c.CipherSuite, 128)
        };
        return new ServiceProbeResult(identification, certificate);
    }

    private async Task ApplyStateAsync(WelesDbContext db, Scan scan, AgentScanState state, int scopeCount, CancellationToken ct)
    {
        scan.HostsTargeted = Math.Clamp(state.HostsTargeted, 0, scopeCount);
        scan.HostsProbed = Math.Clamp(state.HostsProbed, 0, scopeCount);
        scan.PortCount = Math.Clamp(state.PortCount, 0, 65535);
        ProgressOf(scan.Id).SetHostsTotal(scan.HostsTargeted);
        if (state.NetworkFingerprint is { } fp && fp.Length <= 200 && fp.Split(',').All(x => MacPattern().IsMatch(x.Trim())))
        {
            scan.NetworkFingerprint = fp.ToLowerInvariant();
        }

        await db.SaveChangesAsync(ct);
        if (state.Segments is { Count: > 0 } segments)
        {
            var valid = segments.Where(s => s is not null).Take(32)
                .Where(s => TargetParser.TryParse(s.Cidr, out var t, out _) && t.Kind == ScanTargetEntryKind.Cidr
                            && (s.Gateway is null || IPAddress.TryParse(s.Gateway, out _)) && (s.GatewayMac is null || MacPattern().IsMatch(s.GatewayMac)))
                .Select(s => new SegmentInfo(s.Cidr.Trim(), s.Gateway, s.GatewayMac?.ToLowerInvariant(), oui.Lookup(s.GatewayMac)))
                .ToList();
            if (valid.Count > 0) await writer.EnsureSegmentsAsync(valid);
        }
    }

    private async Task<IReadOnlySet<IPAddress>> ScopeOfScanAsync(Scan scan, CancellationToken ct)
    {
        if (_scopeOfScan.TryGetValue(scan.Id, out var cached)) return cached;
        // Agent scopes hold addresses, CIDRs and ranges only – no name is resolved here.
        var resolution = await ScopeResolver.ResolveAsync(Snapshot(scan.ScopeSnapshot), false, scanOptions.Value.MaxHostsPerScan,
            (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>([]), ct);
        var set = resolution.Addresses.ToHashSet();
        _scopeOfScan[scan.Id] = set;
        return set;
    }

    private async Task FinishScanAsync(WelesDbContext db, Scan scan, ScanStatus status, string message, CancellationToken ct)
    {
        scan.Status = status;
        scan.CompletedAt = Now;
        scan.StartedAt ??= scan.CompletedAt;
        if (status == ScanStatus.Failed) scan.ErrorMessage = message.Length > 2000 ? message[..2000] : message;
        await db.SaveChangesAsync(ct);
        await writer.AddEventAsync(scan.Id, status == ScanStatus.Completed ? ScanEventLevel.Info : ScanEventLevel.Warning, message);
        _scopeOfScan.TryRemove(scan.Id, out _);
        coordinator.End(scan.Id);
        logger.LogInformation("Agent scan {ScanId} finished with status {Status}", scan.Id, status);
    }

    private Task AddAgentEventAsync(int scanId, AgentEvent e) =>
        e is null ? Task.CompletedTask : writer.AddEventAsync(scanId, Enum.IsDefined(e.Level) ? e.Level : ScanEventLevel.Info, Clean(e.Message, 500));

    private ScanProgress ProgressOf(int scanId) => coordinator.GetProgress(scanId) ?? coordinator.Begin(scanId, CancellationToken.None).Progress;

    private async Task TouchAsync(WelesDbContext db, int agentId, string remote, CancellationToken ct) =>
        await db.Agents.Where(a => a.Id == agentId).ExecuteUpdateAsync(u => u.SetProperty(a => a.LastSeenAt, Now).SetProperty(a => a.LastAddress, Clean(remote, 64)), ct);

    private void Seen(Agent agent, AgentSystemInfo system, string remote)
    {
        var clean = new AgentSystemInfo(Clean(system.Hostname, 255), Clean(system.OperatingSystem, 200), Clean(system.Architecture, 32), Clean(system.AgentVersion, 50),
            Math.Clamp(system.ProcessorCount, 0, 4096),
            (system.Interfaces ?? []).Where(i => i is not null).Take(32).Select(i => new AgentInterface(Clean(i.Name, 64), Clean(i.Type, 32), Clean(i.Address, 64),
                Math.Clamp(i.PrefixLength, 0, 128), Clean(i.NetworkCidr, 64), CleanOrNull(i.Gateway, 64),
                i.MacAddress is { } mac && MacPattern().IsMatch(mac) ? mac.ToLowerInvariant() : null)).ToList());
        agent.Hostname = clean.Hostname;
        agent.OperatingSystem = clean.OperatingSystem;
        agent.AgentVersion = clean.AgentVersion;
        agent.SystemInfoJson = JsonSerializer.Serialize(clean, AgentProtocol.Json);
        agent.LastSeenAt = Now;
        agent.LastAddress = Clean(remote, 64);
    }

    private static IReadOnlySet<string> MacsOf(Agent agent) =>
        (SystemOf(agent)?.Interfaces ?? []).Select(i => i.MacAddress).OfType<string>().ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static AgentSystemInfo? SystemOf(Agent agent)
    {
        if (agent.SystemInfoJson is null) return null;
        try
        {
            return JsonSerializer.Deserialize<AgentSystemInfo>(agent.SystemInfoJson, AgentProtocol.Json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private AgentView View(Agent a, int scans, int? activeScan) => new(a.Id, a.Name, a.Status,
        a.Status == AgentStatus.Active && a.LastSeenAt is { } seen && Now - seen < OnlineWindow, a.CreatedAt, a.EnrollmentExpiresAt, a.EnrolledAt, a.LastSeenAt,
        a.LastAddress, a.Hostname, a.OperatingSystem, a.AgentVersion, SystemOf(a), a.RevokedAt,
        a.Scopes.Where(s => s.ScanTarget is not null).Select(s => new AgentScopeView(s.ScanTargetId, s.ScanTarget!.Name, s.ScanTarget.IsApproved)).OrderBy(s => s.Name).ToList(),
        scans, activeScan);

    private async Task<string?> ScopeErrorAsync(IReadOnlyCollection<int> scopeIds, CancellationToken ct)
    {
        if (scopeIds.Count == 0) return null;
        var eligible = (await EligibleScopesAsync(ct)).Select(s => s.Id).ToHashSet();
        return scopeIds.All(eligible.Contains) ? null : "Agentowi można przypisać tylko zakres sieci lokalnej (adresy, CIDR, przedziały – bez domen i adresów publicznych).";
    }

    internal static string? ScopeProblem(ScanTarget target) =>
        target.IsExternal || target.AllowPublicAddresses ? "Zakres z adresami publicznymi nie może być skanowany przez agenta."
        : target.Entries.Any(e => e.Kind == ScanTargetEntryKind.Domain) ? "Zakres agenta nie może zawierać nazw domen."
        : null;

    private static List<ScopeEntry> Snapshot(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try
        {
            return JsonSerializer.Deserialize<List<ScopeEntry>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private bool IsThrottled(string remote) =>
        _failures.TryGetValue(remote, out var f) && Now - f.Since < FailureWindow && f.Count >= MaxFailuresPerWindow;

    private void Failed(string remote) => _failures.AddOrUpdate(remote, _ => (1, Now), (_, f) => Now - f.Since >= FailureWindow ? (1, Now) : (f.Count + 1, f.Since));

    /// <summary>256-bit random secret, URL-safe – enrollment codes and access tokens.</summary>
    internal static string NewSecret() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    internal static string Hash(string secret) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    private static string Clean(string? value, int max, bool keepLines = false)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var sb = new StringBuilder(Math.Min(value.Length, max));
        foreach (var c in value)
        {
            if (sb.Length >= max) break;
            sb.Append(char.IsControl(c) && !(keepLines && c is '\n' or '\r' or '\t') ? ' ' : c);
        }

        return sb.ToString();
    }

    private static string? CleanOrNull(string? value, int max, bool keepLines = false) => string.IsNullOrEmpty(value) ? null : Clean(value, max, keepLines);

    [GeneratedRegex("^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")]
    private static partial Regex MacPattern();
}
