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
    ILogger<ScanEngine> logger,
    NmapEngine? nmap = null)
{
    public async Task RunAsync(int scanId, ScanProgress progress, CancellationToken cancellationToken)
    {
        var options = optionsAccessor.Value;
        await using var db = await contextFactory.CreateDbContextAsync(CancellationToken.None);
        var scan = await db.Scans.Include(s => s.ScanTarget!).ThenInclude(t => t.Entries).SingleAsync(s => s.Id == scanId, CancellationToken.None);
        var target = scan.ScanTarget!;

        var resuming = scan.Status == ScanStatus.Paused;
        if (scan.Status != ScanStatus.Pending && !resuming)
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
            if (!resuming) await FinishAsync(db, scan, ScanStatus.Cancelled, 0, "Skan zatrzymany przed rozpoczęciem.");
            return;
        }

        scan.Status = ScanStatus.Running;
        if (resuming)
        {
            // Same scope snapshot and settings as the first part – the resume point refers to that address list.
            await db.SaveChangesAsync(CancellationToken.None);
            await writer.AddEventAsync(scanId, ScanEventLevel.Info, $"Wznowiono skan zakresu „{target.Name}” od adresu {scan.CompletedAddresses + 1} z {scan.HostsTargeted}.");
        }
        else
        {
            scan.StartedAt = Now;
            scan.SettingsJson = JsonSerializer.Serialize(new
            {
                options.MaxConcurrentConnections, options.ConnectionsPerSecond, options.ConnectTimeoutMs,
                options.ParallelHostDiscovery, options.ParallelHostScans, options.UseIcmp,
                Engine = scan.Engine.ToString(), Nmap = scan.Engine == PortEngine.Nmap ? nmap?.Status.Version : null
            });
            scan.ScopeSnapshot = JsonSerializer.Serialize(target.Entries.Select(e => new { e.Value, e.IsExclusion }));
            await db.SaveChangesAsync(CancellationToken.None);

            logger.LogInformation("Scan {ScanId} started for scope {Target} (ports: {Ports})", scanId, target.Name, scan.PortSpecification);
            await writer.AddEventAsync(scanId, ScanEventLevel.Info, $"Rozpoczęto skan zakresu „{target.Name}” (porty: {scan.PortSpecification}).");
        }

        try
        {
            var scanner = new NetworkScanner(oui, localNetwork, options, logger, nmap);
            if (scan.Engine == PortEngine.Nmap && !resuming)
            {
                await writer.AddEventAsync(scanId, ScanEventLevel.Info, nmap is { Status.IsAvailable: true }
                    ? $"Silnik portów i wersji: nmap {nmap.Status.Version} (TCP connect, wykrywanie wersji, bez skryptów NSE); usługi web, sygnatury i podatności – WELES."
                    : "Silnik portów i wersji: wybrano nmap, ale nie jest zainstalowany – skanuje wbudowany silnik WELES.");
            }

            var sink = new DatabaseSink(writer, db, scan);
            var outcome = await scanner.RunAsync(
                new NetworkScanRequest(target.Entries.Select(e => new ScopeEntry(e.Value, e.IsExclusion)).ToList(), target.AllowPublicAddresses, scan.PortSpecification,
                    await Fingerprint.SignatureService.CustomPathsAsync(db, CancellationToken.None), scan.CompletedAddresses,
                    await ExpectedAddressesAsync(db, scan, CancellationToken.None), scan.Engine),
                progress, sink, cancellationToken);
            if (outcome.Error is not null)
            {
                await FailAsync(db, scan, outcome.Error);
                return;
            }

            if (outcome.Paused)
            {
                await db.Entry(scan).ReloadAsync(CancellationToken.None);
                scan.Status = ScanStatus.Paused;
                scan.HostsProbed = progress.HostsProbed;
                await db.SaveChangesAsync(CancellationToken.None);
                logger.LogInformation("Scan {ScanId} paused after {Done} of {Total} addresses", scanId, scan.CompletedAddresses, scan.HostsTargeted);
                return;
            }

            if (progress.HostsAlive == 0 && progress.HostsProbed > 0)
            {
                await writer.AddEventAsync(scanId, ScanEventLevel.Warning,
                    "Nie wykryto żadnych aktywnych hostów. Jeśli zakres jest w innej sieci niż komputer z WELES, wyniki będą puste – sprawdź zakres w Wykrywaniu sieci.");
            }

            if (resuming)
            {
                await FinishAsync(db, scan, ScanStatus.Completed, progress.HostsProbed, $"Skan zakończony po wznowieniu: w całym zakresie {scan.HostsAlive} hostów, {scan.OpenPorts} otwartych portów.");
            }
            else
            {
                await FinishAsync(db, scan, ScanStatus.Completed, progress.HostsProbed,
                    $"Skan zakończony: {progress.HostsAlive} hostów, {progress.OpenPorts} otwartych portów, {progress.ServicesIdentified} rozpoznanych usług.");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await FinishAsync(db, scan, ScanStatus.Cancelled, progress.HostsProbed, $"Skan zatrzymany. Zachowano wyniki dla {progress.HostsCompleted} hostów.");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Scan {ScanId} failed", scanId);
            await FailAsync(db, scan, $"Błąd skanowania: {ex.Message}", progress.HostsProbed);
        }
    }

    /// <summary>
    /// Addresses where hosts answered in earlier completed scans of this scope on the same network – silent ones get a
    /// second probe (unstable hosts). Bounded, so a huge history does not slow the scan down.
    /// </summary>
    private static async Task<IReadOnlySet<IPAddress>> ExpectedAddressesAsync(WelesDbContext db, Scan scan, CancellationToken ct)
    {
        var previous = await db.Scans.AsNoTracking()
            .Where(s => s.ScanTargetId == scan.ScanTargetId && s.Id != scan.Id && s.Status == ScanStatus.Completed)
            .OrderByDescending(s => s.StartedAt).Select(s => s.Id).Take(5).ToListAsync(ct);
        var ips = await db.DiscoveredHosts.AsNoTracking().Where(h => previous.Contains(h.ScanId)).Select(h => h.IpAddress).Distinct().Take(4096).ToListAsync(ct);
        return ips.Select(ip => IPAddress.TryParse(ip, out var a) ? a : null).OfType<IPAddress>().ToHashSet();
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

    private async Task FinishAsync(WelesDbContext db, Scan scan, ScanStatus status, int hostsProbed, string message)
    {
        await db.Entry(scan).ReloadAsync(CancellationToken.None); // counters were updated by the writer
        scan.HostsProbed = hostsProbed; // after the reload – otherwise the in-memory value would be lost
        scan.Status = status;
        scan.CompletedAt = Now;
        await db.SaveChangesAsync(CancellationToken.None);
        await writer.AddEventAsync(scan.Id, status == ScanStatus.Completed ? ScanEventLevel.Info : ScanEventLevel.Warning, message);
        logger.LogInformation("Scan {ScanId} finished with status {Status}: {HostsAlive} hosts, {OpenPorts} open ports", scan.Id, status, scan.HostsAlive, scan.OpenPorts);
    }

    private async Task FailAsync(WelesDbContext db, Scan scan, string message, int? hostsProbed = null)
    {
        await db.Entry(scan).ReloadAsync(CancellationToken.None);
        if (hostsProbed is { } probed) scan.HostsProbed = probed;
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
            scan.NetworkFingerprint ??= fingerprint;
            await db.SaveChangesAsync(CancellationToken.None);
            await writer.EnsureSegmentsAsync(segments);
        }

        public Task HostAsync(HostScanResult host) => writer.SaveHostAsync(scan.Id, host);

        public async Task SubgroupCompletedAsync(int completedAddresses)
        {
            await db.Entry(scan).ReloadAsync(CancellationToken.None); // counters were updated by the writer
            scan.CompletedAddresses = completedAddresses;
            await db.SaveChangesAsync(CancellationToken.None);
        }
    }
}
