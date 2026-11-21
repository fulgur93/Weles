using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Discovery;

namespace Weles.Infrastructure.Scanning;

/// <summary>
/// Runs one approved scan: resolve scope → host discovery → port scan → service identification → persist.
/// </summary>
public sealed class ScanEngine(
    IDbContextFactory<WelesDbContext> contextFactory,
    ScanResultWriter writer,
    OuiDatabase oui,
    LocalNetworkDiscovery localNetwork,
    IOptions<ScanOptions> optionsAccessor,
    TimeProvider timeProvider,
    ILogger<ScanEngine> logger)
{
    public async Task RunAsync(int scanId, ScanProgress progress, CancellationToken cancellationToken)
    {
        var options = optionsAccessor.Value;
        await using var db = await contextFactory.CreateDbContextAsync(CancellationToken.None);
        var scan = await db.Scans.Include(s => s.ScanTarget!).ThenInclude(t => t.Entries).SingleAsync(s => s.Id == scanId, CancellationToken.None);
        var target = scan.ScanTarget!;

        if (scan.Status != ScanStatus.Pending)
        {
            logger.LogWarning("Scan {ScanId} is in state {Status} and will not be started", scanId, scan.Status);
            return;
        }

        if (!target.IsApproved)
        {
            await FailAsync(db, scan, "Zakres skanowania nie jest zatwierdzony – skan odrzucony.");
            return;
        }

        if (cancellationToken.IsCancellationRequested)
        {
            await FinishAsync(db, scan, ScanStatus.Cancelled, "Skan zatrzymany przed rozpoczęciem.");
            return;
        }

        scan.Status = ScanStatus.Running;
        scan.StartedAt = Now;
        scan.SettingsJson = JsonSerializer.Serialize(new
        {
            options.MaxConcurrentConnections, options.ConnectionsPerSecond, options.ConnectTimeoutMs,
            options.ParallelHostDiscovery, options.ParallelHostScans, options.UseIcmp
        });
        scan.ScopeSnapshot = JsonSerializer.Serialize(target.Entries.Select(e => new { e.Value, e.IsExclusion }));
        await db.SaveChangesAsync(CancellationToken.None);

        logger.LogInformation("Scan {ScanId} started for scope {Target} (ports: {Ports})", scanId, target.Name, scan.PortSpecification);
        await writer.AddEventAsync(scanId, ScanEventLevel.Info, $"Rozpoczęto skan zakresu „{target.Name}” (porty: {scan.PortSpecification}).");

        try
        {
            var scanner = new NetworkScanner(oui, localNetwork, options, logger);
            var sink = new DatabaseSink(writer, db, scan);
            var outcome = await scanner.RunAsync(
                new NetworkScanRequest(target.Entries.Select(e => new ScopeEntry(e.Value, e.IsExclusion)).ToList(), target.AllowPublicAddresses, scan.PortSpecification,
                    await Fingerprint.SignatureService.CustomPathsAsync(db, CancellationToken.None)),
                progress, sink, cancellationToken);
            if (outcome.Error is not null)
            {
                await FailAsync(db, scan, outcome.Error);
                return;
            }

            scan.HostsProbed = progress.HostsProbed;
            await FinishAsync(db, scan, ScanStatus.Completed,
                $"Skan zakończony: {progress.HostsAlive} hostów, {progress.OpenPorts} otwartych portów, {progress.ServicesIdentified} rozpoznanych usług.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            scan.HostsProbed = progress.HostsProbed;
            await FinishAsync(db, scan, ScanStatus.Cancelled, $"Skan zatrzymany. Zachowano wyniki dla {progress.HostsCompleted} hostów.");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Scan {ScanId} failed", scanId);
            await FailAsync(db, scan, $"Błąd skanowania: {ex.Message}");
        }
    }

    /// <summary>Gateway MAC of every local interface whose network contains part of the scope.</summary>
    internal static string? NetworkFingerprint(IReadOnlyList<LocalInterfaceInfo> interfaces, IReadOnlyList<IPAddress> scope, IReadOnlyDictionary<IPAddress, string> arp)
    {
        var scopeValues = scope.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Select(Ipv4.ToUInt).ToList();
        var macs = interfaces
            .Where(i => i.Gateway is not null && IPAddress.TryParse(i.Address, out _))
            .Where(i =>
            {
                var range = Ipv4.CidrRange(Ipv4.ToUInt(IPAddress.Parse(i.Address)), i.PrefixLength, hostsOnly: false);
                return scopeValues.Any(range.Contains);
            })
            .Select(i => IPAddress.TryParse(i.Gateway, out var gw) ? arp.GetValueOrDefault(gw) : null);
        return Core.Networking.NetworkIdentity.Fingerprint(macs);
    }

    /// <summary>The device's own announcement names a service that did not identify itself to the probes.</summary>
    internal static Core.Models.ServiceIdentification WithMdnsHint(Core.Models.ServiceIdentification id, MdnsService announced)
    {
        var entry = MdnsServiceCatalog.Find(announced.Type);
        id.Extra["mdns.service"] = entry?.Label ?? announced.Type;
        id.Extra["mdns.instance"] = announced.Instance;
        if (announced.Txt.Count > 0) id.Extra["mdns.txt"] = string.Join("; ", announced.Txt.Take(8)) is var t && t.Length > 300 ? t[..300] : t;
        if (entry?.IsRisky == true) id.Extra["mdns.risky"] = "true";

        var weak = id.Method is "port-hint" or "banner-unrecognized" or "tls-handshake";
        return !weak || entry is null ? id : id with
        {
            ServiceName = id.IsTls && !entry.ServiceName.Contains("tls") ? $"ssl/{entry.ServiceName}" : entry.ServiceName,
            OsHint = id.OsHint ?? entry.Os,
            Confidence = Math.Max(id.Confidence, 70),
            Method = id.Method + "+mdns"
        };
    }

    private async Task FinishAsync(WelesDbContext db, Scan scan, ScanStatus status, string message)
    {
        await db.Entry(scan).ReloadAsync(CancellationToken.None); // counters were updated by the writer
        scan.Status = status;
        scan.CompletedAt = Now;
        await db.SaveChangesAsync(CancellationToken.None);
        await writer.AddEventAsync(scan.Id, status == ScanStatus.Completed ? ScanEventLevel.Info : ScanEventLevel.Warning, message);
        logger.LogInformation("Scan {ScanId} finished with status {Status}: {HostsAlive} hosts, {OpenPorts} open ports", scan.Id, status, scan.HostsAlive, scan.OpenPorts);
    }

    private async Task FailAsync(WelesDbContext db, Scan scan, string message)
    {
        await db.Entry(scan).ReloadAsync(CancellationToken.None);
        scan.Status = ScanStatus.Failed;
        scan.ErrorMessage = message.Length > 2000 ? message[..2000] : message;
        scan.CompletedAt = Now;
        await db.SaveChangesAsync(CancellationToken.None);
        await writer.AddEventAsync(scan.Id, ScanEventLevel.Error, message);
        logger.LogWarning("Scan {ScanId} failed: {Message}", scan.Id, message);
    }

    private DateTime Now => timeProvider.GetUtcNow().UtcDateTime;

    /// <summary>Stores what the scanner finds in the central database as it goes.</summary>
    private sealed class DatabaseSink(ScanResultWriter writer, WelesDbContext db, Scan scan) : IScanSink
    {
        public Task EventAsync(ScanEventLevel level, string message) => writer.AddEventAsync(scan.Id, level, message);

        public async Task ScopeResolvedAsync(int hostsTargeted, int portCount)
        {
            scan.HostsTargeted = hostsTargeted;
            scan.PortCount = portCount;
            await db.SaveChangesAsync(CancellationToken.None);
        }

        public async Task NetworkAsync(string? fingerprint, IReadOnlyList<SegmentInfo> segments)
        {
            scan.NetworkFingerprint = fingerprint;
            await db.SaveChangesAsync(CancellationToken.None);
            await writer.EnsureSegmentsAsync(segments);
        }

        public Task HostAsync(HostScanResult host) => writer.SaveHostAsync(scan.Id, host);
    }
}
