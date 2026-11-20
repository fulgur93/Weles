using System.Reflection;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Reports;
using Weles.Core.Risk;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Queries;

namespace Weles.Infrastructure.Reports;

/// <summary>
/// Builds the <see cref="AuditDocument"/> of one completed scan from the database – the state as that scan saw it:
/// its hosts and services, the risk assessed right after it, CVE matches and configuration findings that were open at
/// that time, and the changes since the previous scan of the same network. Later scans do not change an older audit.
/// </summary>
public sealed class AuditDocumentBuilder(
    IDbContextFactory<WelesDbContext> contextFactory,
    NetworkQueries networks,
    MonitoringQueries monitoring,
    TimeProvider time)
{
    public const int MaxRecommendations = 30;

    public static string GeneratorName { get; } =
        "WELES " + (typeof(AuditDocumentBuilder).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
                    ?? typeof(AuditDocumentBuilder).Assembly.GetName().Version?.ToString(3) ?? "");

    private sealed record ScopeEntry(string Value, bool IsExclusion);

    /// <summary>Null when the scan does not exist or has not completed.</summary>
    public async Task<AuditDocument?> BuildAsync(int scanId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var scan = await db.Scans.AsNoTracking().Include(s => s.ScanTarget)
            .SingleOrDefaultAsync(s => s.Id == scanId && s.Status == ScanStatus.Completed, ct);
        if (scan is null) return null;

        var started = scan.StartedAt ?? scan.CreatedAt;
        // Matching and risk run right after the scan – what they stored in that window belongs to this audit.
        var end = (scan.CompletedAt ?? started) + MonitoringQueries.MatchingWindow;

        var hosts = await db.DiscoveredHosts.AsNoTracking().AsSplitQuery().Where(h => h.ScanId == scanId)
            .Include(h => h.Ports).ThenInclude(p => p.Service).ThenInclude(s => s!.Certificates)
            .OrderBy(h => h.Id).ToListAsync(ct);
        var assetIds = hosts.Where(h => h.AssetId != null).Select(h => h.AssetId!.Value).Distinct().ToList();
        var assets = await db.Assets.AsNoTracking().Where(a => assetIds.Contains(a.Id)).ToDictionaryAsync(a => a.Id, ct);

        var scores = await db.RiskScores.AsNoTracking().Where(r => r.ScanId == scanId).Select(r => new { r.AssetId, r.Score, r.BreakdownJson }).ToListAsync(ct);
        var results = scores.Where(r => r.AssetId != null).Select(r => (Id: r.AssetId!.Value, Result: RiskQueries.Result(r.BreakdownJson)))
            .Where(r => r.Result is not null).GroupBy(r => r.Id).ToDictionary(g => g.Key, g => g.First().Result!);

        var vulnerabilities = await db.AssetVulnerabilities.AsNoTracking()
            .Where(v => assetIds.Contains(v.AssetId) && v.FirstDetectedAt <= end && (v.ResolvedAt == null || v.ResolvedAt > end))
            .Select(v => new
            {
                v.AssetId, v.Vulnerability!.CveId, v.Vulnerability.Title, v.Vulnerability.Description, v.Vulnerability.CvssScore, v.Vulnerability.Severity,
                v.Vulnerability.EpssScore, v.Vulnerability.IsKnownExploited, v.MatchStatus, v.MatchConfidence, v.MatchReason, v.Port, v.Product, v.DetectedVersion, v.Status
            })
            .ToListAsync(ct);
        var findings = await db.RiskFindings.AsNoTracking()
            .Where(f => assetIds.Contains(f.AssetId) && f.CreatedAt <= end && (f.ResolvedAt == null || f.ResolvedAt > end))
            .ToListAsync(ct);

        var devices = new List<AuditDevice>();
        var assessed = new List<(Asset Asset, AssetRiskResult Result)>();
        foreach (var group in hosts.GroupBy(h => h.AssetId ?? -h.Id))
        {
            var host = group.First();
            var asset = host.AssetId is { } id ? assets.GetValueOrDefault(id) : null;
            var result = asset is null ? null : results.GetValueOrDefault(asset.Id);
            if (asset is not null && result is not null) assessed.Add((asset, result));

            var services = group.SelectMany(h => h.Ports).Where(p => p.State == PortState.Open).DistinctBy(p => (p.Port, p.Protocol)).OrderBy(p => p.Port)
                .Select(p => new AuditService(p.Port, p.Protocol, p.Service?.ServiceName, p.Service?.Product, p.Service?.Version, p.Service?.Confidence ?? 0,
                    p.Service?.IsTls ?? false, p.Service?.Certificates.OrderBy(c => c.Id).Select(c =>
                        new AuditCertificate(c.Subject, c.Issuer, c.NotAfter, c.IsSelfSigned, c.HostnameMatches, c.TlsProtocol)).FirstOrDefault()))
                .ToList();

            var cves = asset is null ? [] : vulnerabilities.Where(v => v.AssetId == asset.Id)
                .Select(v => new AuditVulnerability(v.CveId, v.Title ?? Shorten(v.Description, 160), v.CvssScore, v.Severity, v.EpssScore, v.IsKnownExploited,
                    v.MatchStatus, v.MatchConfidence, v.MatchReason, v.Port, v.Product, v.DetectedVersion,
                    // Resolved later – at audit time it was still open.
                    v.Status == FindingStatus.Resolved ? FindingStatus.Open : v.Status))
                .OrderByDescending(v => v.IsKnownExploited).ThenByDescending(v => v.CvssScore ?? 0).ThenBy(v => v.CveId, StringComparer.Ordinal).ToList();

            var configuration = asset is null ? [] : findings.Where(f => f.AssetId == asset.Id)
                .Select(f => new AuditFinding(f.RuleId, f.Title, f.Level, f.Score, f.Port, f.Evidence, f.Recommendation,
                    f.Status == FindingStatus.Resolved ? FindingStatus.Open : f.Status))
                .OrderByDescending(f => f.Score).ThenBy(f => f.Port).ToList();

            var name = asset is null ? host.Hostname ?? host.IpAddress : asset.CustomName ?? asset.DisplayName;
            // One device can answer on several addresses in a scan (e.g. Wi‑Fi and Ethernet) – all of them are listed.
            var addresses = string.Join(", ", group.Select(h => h.IpAddress).Distinct());
            devices.Add(new AuditDevice(name, addresses, host.Hostname ?? asset?.Hostname, host.MacAddress ?? asset?.MacAddress, host.Vendor ?? asset?.Vendor,
                asset?.EffectiveType ?? host.AssetTypeGuess, asset?.OsFamily ?? host.OsGuess, asset?.Model, asset?.Criticality ?? AssetCriticality.Medium,
                group.Any(h => h.IsGateway), result?.Score, result?.Level, result?.Factors ?? [], services, cves, configuration));
        }

        devices = devices.OrderByDescending(d => d.RiskScore ?? -1).ThenBy(d => d.Name, StringComparer.Ordinal).ToList();

        var recommendations = RiskQueries.Prioritize(assessed).Take(MaxRecommendations)
            .Select(r => new AuditRecommendation(r.AssetName, r.AssetIp, r.Issue.Title, r.Priority, r.Level, r.Issue.Port, r.Issue.Recommendation,
                r.Issue.CveIds ?? [], r.Issue.KnownExploited))
            .ToList();

        var changes = await ChangesAsync(scanId, ct);
        var posture = scores.FirstOrDefault(r => r.AssetId == null) is { } p
            ? new AuditPosture(p.Score, changes?.PostureBefore, PostureFactors(p.BreakdownJson))
            : null;

        var context = await networks.ContextAsync(ct);
        var network = context.LabelOf(context.ScanNetworkKey(scanId));
        var summary = await db.AuditAiSummaries.AsNoTracking().Where(s => s.ScanId == scanId)
            .Select(s => new AuditAiSummaryInfo(s.Text, s.Model, s.Language, s.CreatedAt)).SingleOrDefaultAsync(ct);

        var info = new AuditInfo(scan.Id, scan.ScanTarget?.Name ?? "#" + scan.ScanTargetId, Scope(scan.ScopeSnapshot), network, scan.ScanTarget?.IsExternal ?? false,
            started, scan.CompletedAt, scan.PortSpecification, scan.Trigger, scan.HostsTargeted, scan.HostsAlive, scan.OpenPorts, scan.IsDemo);
        return new AuditDocument(AuditDocument.FormatName, AuditDocument.CurrentSchemaVersion, time.GetUtcNow().UtcDateTime, GeneratorName,
            info, posture, devices, recommendations, changes, summary);
    }

    private async Task<AuditChanges?> ChangesAsync(int scanId, CancellationToken ct)
    {
        if (await monitoring.PreviousOnSameNetworkAsync(scanId, ct) is not { } previous) return null;
        if (await monitoring.CompareAsync(previous, scanId, ct) is not { } c) return null;

        static string Device(DeviceRef d) => d.Ip is null || d.Name.Contains(d.Ip, StringComparison.Ordinal) ? d.Name : $"{d.Name} ({d.Ip})";
        var items = new List<AuditChange>();
        items.AddRange(c.NewDevices.Select(d => new AuditChange(AuditChangeKind.NewDevice, Device(d), "Nowe urządzenie w sieci")));
        items.AddRange(c.ReturnedDevices.Select(d => new AuditChange(AuditChangeKind.ReturnedDevice, Device(d), "Urządzenie pojawiło się ponownie")));
        items.AddRange(c.MissingDevices.Select(d => new AuditChange(AuditChangeKind.MissingDevice, Device(d), "Nie wykryto urządzenia (adres był w zakresie skanu)")));
        foreach (var device in c.Changed)
        {
            items.AddRange(device.Changes.Select(x => new AuditChange(x.Kind switch
            {
                AssetChangeKind.PortOpened => AuditChangeKind.PortOpened,
                AssetChangeKind.PortClosed => AuditChangeKind.PortClosed,
                AssetChangeKind.ServiceChanged => AuditChangeKind.ServiceChanged,
                AssetChangeKind.VersionChanged => AuditChangeKind.VersionChanged,
                AssetChangeKind.CertificateChanged => AuditChangeKind.CertificateChanged,
                _ => AuditChangeKind.OtherChange
            }, Device(device.Device), x.Description)));
        }

        static string Cve(VulnerabilityChange v) => v.CveId + (v.Product is null ? "" : $" ({v.Product} {v.Version})".TrimEnd()) + (v.IsKnownExploited ? " – CISA KEV" : "");
        items.AddRange(c.NewVulnerabilities.Select(v => new AuditChange(AuditChangeKind.NewVulnerability, Device(v.Device), Cve(v))));
        items.AddRange(c.ResolvedVulnerabilities.Select(v => new AuditChange(AuditChangeKind.ResolvedVulnerability, Device(v.Device), Cve(v))));
        items.AddRange(c.RiskChanges.Select(r => new AuditChange(AuditChangeKind.RiskChanged, Device(r.Device),
            r.Before is { } before ? $"Ryzyko {before:0} → {r.After:0}" : $"Ryzyko {r.After:0}")));
        return new AuditChanges(c.Previous.Id, c.Previous.At, c.PostureBefore, c.PostureAfter, items);
    }

    private static IReadOnlyList<string> Scope(string? snapshot)
    {
        if (string.IsNullOrWhiteSpace(snapshot)) return [];
        try
        {
            return (JsonSerializer.Deserialize<List<ScopeEntry>>(snapshot) ?? [])
                .Select(e => e.IsExclusion ? "wyklucz " + e.Value : e.Value).ToList();
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static IReadOnlyList<RiskFactor> PostureFactors(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<Risk.PostureBreakdown>(json, Risk.RiskAssessmentService.Json)?.Factors ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static string? Shorten(string? text, int max) =>
        string.IsNullOrWhiteSpace(text) ? null : text.Length <= max ? text : text[..(max - 1)].TrimEnd() + "…";
}
