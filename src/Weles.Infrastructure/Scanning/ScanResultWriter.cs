using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Database;

namespace Weles.Infrastructure.Scanning;

/// <summary>
/// Persists scan observations and correlates them with stable assets. Writes are serialized
/// (SQLite has a single writer) and never cancelled half-way, so partial results survive a stop.
/// </summary>
/// <param name="Gateway">Gateway IP.</param>
public sealed record SegmentInfo(string Cidr, string? Gateway, string? GatewayMac, string? GatewayVendor);

public sealed class ScanResultWriter(IDbContextFactory<WelesDbContext> contextFactory, TimeProvider timeProvider)
{
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public async Task AddEventAsync(int scanId, ScanEventLevel level, string message)
    {
        await _writeLock.WaitAsync();
        try
        {
            await using var db = await contextFactory.CreateDbContextAsync();
            db.ScanEvents.Add(new ScanEvent { ScanId = scanId, Level = level, Message = message.Length > 1000 ? message[..1000] : message, Timestamp = Now });
            await db.SaveChangesAsync();
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task SaveHostAsync(int scanId, HostScanResult result)
    {
        await _writeLock.WaitAsync();
        try
        {
            await using var db = await contextFactory.CreateDbContextAsync();
            var now = Now;
            var ip = result.Address.ToString();

            var host = new DiscoveredHost
            {
                ScanId = scanId,
                IpAddress = ip,
                Hostname = Truncate(result.Hostname, 255),
                MacAddress = result.MacAddress,
                Vendor = Truncate(result.Vendor, 255),
                DiscoveryMethods = result.Methods,
                RoundTripMs = result.RoundTripMs,
                Ttl = result.Ttl,
                OsGuess = result.Classification.OsFamily,
                IsGateway = result.IsGateway,
                AssetTypeGuess = result.Classification.Type,
                ClassificationConfidence = result.Classification.Confidence,
                ClassificationReasons = Truncate(string.Join('\n', result.Classification.Reasons), 2000),
                AnnouncedServicesJson = result.AnnouncedServices is { Count: > 0 } announced
                    ? Truncate(JsonSerializer.Serialize(announced.Take(30).Select(a => new { a.Type, a.Instance, a.Port })), 4000)
                    : null,
                DiscoveredAt = now,
                Ports = result.OpenPorts.Select(p => ToEntity(p)).ToList()
            };

            var network = await db.Scans.Where(s => s.Id == scanId).Select(s => s.NetworkFingerprint).SingleOrDefaultAsync();
            var asset = result.IsLocalMachine
                ? await ConsolidateLocalMachineAsync(db, result.LocalMacAddresses!, result.MacAddress)
                : null;
            asset ??= await FindAssetAsync(db, ip, result.MacAddress, result.Hostname, network);
            if (!result.IsLocalMachine && HostKeyOf(result) is { } hostKey)
            {
                asset = await ConsolidateBySshHostKeyAsync(db, hostKey, result.MacAddress, asset);
            }

            if (asset is null)
            {
                asset = new Asset { DisplayName = ip, FirstSeenAt = now };
                db.Assets.Add(asset);
            }

            asset.PrimaryIpAddress = ip;
            asset.Hostname = result.Hostname ?? asset.Hostname;
            // This machine changes interfaces (Wi‑Fi / cable): keep the MAC of the interface it was found on now.
            asset.MacAddress = result.IsLocalMachine ? result.MacAddress ?? asset.MacAddress : asset.MacAddress ?? result.MacAddress;
            asset.Vendor = result.Vendor ?? asset.Vendor;
            if (result.Classification.Confidence > 0)
            {
                asset.AssetType = result.Classification.Type;
                asset.ClassificationReasons = host.ClassificationReasons;
            }

            asset.OsFamily = result.Classification.OsFamily ?? asset.OsFamily;
            var model = result.OpenPorts.Select(p => p.Service?.Identification.Extra.GetValueOrDefault("device.model") ?? p.Service?.Identification.Extra.GetValueOrDefault("adb.model"))
                .FirstOrDefault(m => !string.IsNullOrWhiteSpace(m));
            asset.Model = model is null ? asset.Model : Truncate(model, 128);
            // A name or type set by the user is never overwritten by a scan.
            asset.DisplayName = AssetNaming.DisplayName(asset.CustomName, asset.Hostname, AssetNaming.Label(asset.Model, asset.Vendor), ip);
            asset.LastSeenAt = now;
            asset.NetworkSegmentId = await FindSegmentIdAsync(db, result.Address, network) ?? asset.NetworkSegmentId;

            host.Asset = asset;
            db.DiscoveredHosts.Add(host);
            await db.SaveChangesAsync();

            var openCount = result.OpenPorts.Count;
            await db.Scans.Where(s => s.Id == scanId).ExecuteUpdateAsync(u => u
                .SetProperty(s => s.HostsAlive, s => s.HostsAlive + 1)
                .SetProperty(s => s.OpenPorts, s => s.OpenPorts + openCount));
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Creates network segments (idempotent). A segment is a CIDR on a specific network (gateway MAC); a segment created
    /// earlier without a known gateway is adopted by the first network that reports one.
    /// </summary>
    public async Task EnsureSegmentsAsync(IEnumerable<SegmentInfo> segments)
    {
        await _writeLock.WaitAsync();
        try
        {
            await using var db = await contextFactory.CreateDbContextAsync();
            var now = Now;
            // The same CIDR can come from the scope (no gateway IP) and from a local interface (with gateway) – keep the gateway.
            var merged = segments.GroupBy(s => (s.Cidr, Mac: s.GatewayMac?.ToLowerInvariant()))
                .Select(g => new SegmentInfo(g.Key.Cidr, g.Select(x => x.Gateway).FirstOrDefault(x => x is not null), g.Key.Mac, g.Select(x => x.GatewayVendor).FirstOrDefault(x => x is not null)));
            foreach (var info in merged)
            {
                var sameCidr = await db.NetworkSegments.Where(s => s.Cidr == info.Cidr).ToListAsync();
                var existing = sameCidr.FirstOrDefault(s => s.GatewayMac == info.GatewayMac)
                    ?? (info.GatewayMac is not null && sameCidr.All(s => s.GatewayMac is null) ? sameCidr.FirstOrDefault() : null);
                if (existing is null)
                {
                    db.NetworkSegments.Add(new NetworkSegment
                    {
                        Cidr = info.Cidr, Gateway = info.Gateway, GatewayMac = info.GatewayMac, GatewayVendor = Truncate(info.GatewayVendor, 255),
                        FirstSeenAt = now, LastSeenAt = now
                    });
                }
                else
                {
                    existing.LastSeenAt = now;
                    existing.Gateway ??= info.Gateway;
                    existing.GatewayMac ??= info.GatewayMac;
                    existing.GatewayVendor ??= Truncate(info.GatewayVendor, 255);
                }
            }

            await db.SaveChangesAsync();
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Identity rules: same MAC → same asset. Without a MAC: same IP on the same network (gateway fingerprint) and no
    /// conflicting MAC/hostname. Otherwise a new asset is created (a different device took the address).
    /// </summary>
    internal static async Task<Asset?> FindAssetAsync(WelesDbContext db, string ip, string? mac, string? hostname, string? network = null)
    {
        if (mac is not null)
        {
            var byMac = await db.Assets.Where(a => a.MacAddress == mac).OrderByDescending(a => a.LastSeenAt).FirstOrDefaultAsync();
            if (byMac is not null) return byMac;
        }

        var byIp = await db.Assets.Where(a => a.PrimaryIpAddress == ip).OrderByDescending(a => a.LastSeenAt).ToListAsync();
        var candidates = byIp.Where(a =>
            (a.MacAddress is null || mac is null || a.MacAddress == mac) &&
            (a.Hostname is null || hostname is null || string.Equals(a.Hostname, hostname, StringComparison.OrdinalIgnoreCase))).ToList();
        if (candidates.Count == 0 || network is null) return candidates.FirstOrDefault();

        var ids = candidates.Select(a => a.Id).ToList();
        var networks = (await db.DiscoveredHosts
                .Where(h => h.AssetId != null && ids.Contains(h.AssetId.Value))
                .Select(h => new { AssetId = h.AssetId!.Value, h.DiscoveredAt, h.Scan!.NetworkFingerprint })
                .ToListAsync())
            .GroupBy(h => h.AssetId)
            .ToDictionary(g => g.Key, g => g.OrderBy(h => h.DiscoveredAt).Last().NetworkFingerprint);
        return candidates.FirstOrDefault(a => NetworkIdentity.SameNetwork(networks.GetValueOrDefault(a.Id), network));
    }

    /// <summary>
    /// The machine running WELES is one asset whichever interface it was found on: assets carrying any of its MAC
    /// addresses are merged into the oldest one (observations, findings and user-entered fields are kept).
    /// </summary>
    internal static async Task<Asset?> ConsolidateLocalMachineAsync(WelesDbContext db, IReadOnlySet<string> localMacs, string? currentMac)
    {
        var macs = localMacs.Select(m => m.ToLowerInvariant()).Append(currentMac?.ToLowerInvariant()).OfType<string>().Distinct().ToList();
        var assets = await db.Assets.Where(a => a.MacAddress != null && macs.Contains(a.MacAddress.ToLower()))
            .OrderBy(a => a.FirstSeenAt).ThenBy(a => a.Id).ToListAsync();
        if (assets.Count <= 1) return assets.FirstOrDefault();

        return await MergeIntoOldestAsync(db, assets);
    }

    /// <summary>SSH host key fingerprint the scan read from the host (see <see cref="SshHostKeyProbe"/>).</summary>
    internal static string? HostKeyOf(HostScanResult result) =>
        result.OpenPorts.Select(p => p.Service?.Identification.Extra.GetValueOrDefault("ssh.hostKey")).FirstOrDefault(k => !string.IsNullOrEmpty(k));

    /// <summary>
    /// One SSH host key = one operating system installation, so assets presenting the same key (e.g. a Raspberry Pi on
    /// cable and on Wi‑Fi, two MAC addresses) are one device and are merged into the oldest record. Guard: some vendors
    /// ship the same key on every unit, so only assets whose MAC addresses share the vendor prefix (OUI) are merged.
    /// </summary>
    internal static async Task<Asset?> ConsolidateBySshHostKeyAsync(WelesDbContext db, string hostKey, string? mac, Asset? found)
    {
        var candidates = await db.DiscoveredServices.AsNoTracking()
            .Where(s => s.ExtraInfoJson != null && s.ExtraInfoJson.Contains("ssh.hostKey") && s.Port!.Host!.AssetId != null)
            .Select(s => new { AssetId = s.Port!.Host!.AssetId!.Value, s.ExtraInfoJson })
            .ToListAsync();
        var ids = candidates.Where(c => KeyIn(c.ExtraInfoJson) == hostKey).Select(c => c.AssetId).Distinct().ToList();
        if (found is not null && !ids.Contains(found.Id)) ids.Add(found.Id);
        if (ids.Count == 0) return found;

        var assets = await db.Assets.Where(a => ids.Contains(a.Id)).OrderBy(a => a.FirstSeenAt).ThenBy(a => a.Id).ToListAsync();
        var oui = Oui(mac ?? found?.MacAddress);
        assets = assets.Where(a => Oui(a.MacAddress) is null || oui is null || Oui(a.MacAddress) == oui).ToList();
        if (assets.Count == 0) return found;
        if (assets.Count == 1) return found ?? assets[0];
        return await MergeIntoOldestAsync(db, assets);
    }

    private static string? KeyIn(string? extraJson)
    {
        try
        {
            return extraJson is null ? null : JsonSerializer.Deserialize<Dictionary<string, string>>(extraJson)?.GetValueOrDefault("ssh.hostKey");
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? Oui(string? mac) => mac is { Length: >= 8 } ? mac[..8].ToLowerInvariant() : null;

    /// <summary>Merges assets into the first (oldest): observations, findings and scores move, user-entered fields are kept.</summary>
    private static async Task<Asset> MergeIntoOldestAsync(WelesDbContext db, List<Asset> assets)
    {
        var target = assets[0];
        foreach (var other in assets.Skip(1))
        {
            target.CustomName ??= other.CustomName;
            target.UserAssetType ??= other.UserAssetType;
            target.Notes = string.IsNullOrWhiteSpace(target.Notes) ? other.Notes
                : string.IsNullOrWhiteSpace(other.Notes) ? target.Notes : Truncate($"{target.Notes}\n{other.Notes}", 4000);
            if (other.Criticality > target.Criticality) target.Criticality = other.Criticality;
            target.Model ??= other.Model;
            if (other.LastSeenAt > target.LastSeenAt) target.LastSeenAt = other.LastSeenAt;

            var otherId = other.Id;
            await db.DiscoveredHosts.Where(h => h.AssetId == otherId).ExecuteUpdateAsync(u => u.SetProperty(h => h.AssetId, target.Id));
            var existingFindings = await db.RiskFindings.Where(f => f.AssetId == target.Id).Select(f => new { f.RuleId, f.Port }).ToListAsync();
            foreach (var f in await db.RiskFindings.Where(f => f.AssetId == otherId).ToListAsync())
            {
                if (existingFindings.Any(e => e.RuleId == f.RuleId && e.Port == f.Port)) db.RiskFindings.Remove(f);
                else f.AssetId = target.Id;
            }

            var targetScans = await db.RiskScores.Where(r => r.AssetId == target.Id).Select(r => r.ScanId).ToListAsync();
            await db.RiskScores.Where(r => r.AssetId == otherId && targetScans.Contains(r.ScanId)).ExecuteDeleteAsync();
            await db.RiskScores.Where(r => r.AssetId == otherId).ExecuteUpdateAsync(u => u.SetProperty(r => r.AssetId, target.Id));
            var existing = await db.AssetVulnerabilities.Where(v => v.AssetId == target.Id).Select(v => v.VulnerabilityId).ToListAsync();
            foreach (var v in await db.AssetVulnerabilities.Where(v => v.AssetId == otherId).ToListAsync())
            {
                if (existing.Contains(v.VulnerabilityId)) db.AssetVulnerabilities.Remove(v);
                else v.AssetId = target.Id;
            }

            await db.SaveChangesAsync();
            db.Assets.Remove(other);
        }

        await db.SaveChangesAsync();
        return target;
    }

    /// <summary>Most specific segment containing the address on this scan's network (or one whose network is unknown).</summary>
    internal static async Task<int?> FindSegmentIdAsync(WelesDbContext db, IPAddress address, string? network)
    {
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return null;
        var value = Ipv4.ToUInt(address);
        var segments = await db.NetworkSegments.AsNoTracking().Select(s => new { s.Id, s.Cidr, s.GatewayMac }).ToListAsync();
        return segments
            .Select(s => (s.Id, s.GatewayMac, Parsed: TargetParser.TryParse(s.Cidr, out var t, out _) ? t : null))
            .Where(s => s.Parsed?.Ipv4Range is { } r && Ipv4.CidrRange(r.Start, PrefixOf(s.Parsed.Normalized), false).Contains(value))
            .Where(s => NetworkIdentity.SameNetwork(s.GatewayMac, network))
            .OrderByDescending(s => PrefixOf(s.Parsed!.Normalized))
            .ThenByDescending(s => s.GatewayMac is not null && network is not null)
            .Select(s => (int?)s.Id)
            .FirstOrDefault();
    }

    private static int PrefixOf(string cidr) => int.Parse(cidr[(cidr.IndexOf('/') + 1)..]);

    private static DiscoveredPort ToEntity(PortScanResult p)
    {
        var port = new DiscoveredPort { Port = p.Port, Protocol = TransportProtocol.Tcp, State = PortState.Open, Reason = p.Reason };
        if (p.Service is { } probe)
        {
            var id = probe.Identification;
            port.Service = new DiscoveredService
            {
                ServiceName = Truncate(id.ServiceName, 100),
                Product = Truncate(id.Product, 255),
                Vendor = Truncate(id.Vendor, 255),
                Version = Truncate(id.Version, 100),
                Cpe = Truncate(id.Cpe, 500),
                Banner = Truncate(id.Banner, 1024),
                Confidence = Math.Clamp(id.Confidence, 0, 100),
                DetectionMethod = Truncate(id.Method, 100),
                IsTls = id.IsTls || probe.Certificate is not null,
                ExtraInfoJson = BuildExtra(id),
            };

            if (probe.Certificate is { } c)
            {
                port.Service.Certificates.Add(new Certificate
                {
                    Subject = Truncate(c.Subject, 1000)!,
                    Issuer = Truncate(c.Issuer, 1000)!,
                    NotBefore = c.NotBefore,
                    NotAfter = c.NotAfter,
                    Thumbprint = c.Thumbprint,
                    SerialNumber = Truncate(c.SerialNumber, 128),
                    SubjectAlternativeNames = Truncate(string.Join(", ", c.SubjectAlternativeNames), 4000),
                    KeyAlgorithm = Truncate(c.KeyAlgorithm, 64),
                    KeySize = c.KeySize,
                    SignatureAlgorithm = Truncate(c.SignatureAlgorithm, 128),
                    TlsProtocol = Truncate(c.TlsProtocol, 32),
                    IsSelfSigned = c.IsSelfSigned,
                    HostnameMatches = c.HostnameMatches
                });
            }
        }

        return port;
    }

    private static string? BuildExtra(Core.Models.ServiceIdentification id)
    {
        var extra = new Dictionary<string, string>(id.Extra);
        if (id.DistributionHint is not null) extra["distribution"] = id.DistributionHint;
        if (id.OsHint is not null) extra["osHint"] = id.OsHint;
        return extra.Count == 0 ? null : JsonSerializer.Serialize(extra);
    }

    private DateTime Now => timeProvider.GetUtcNow().UtcDateTime;

    private static string? Truncate(string? value, int max) => value is null || value.Length <= max ? value : value[..max];
}
