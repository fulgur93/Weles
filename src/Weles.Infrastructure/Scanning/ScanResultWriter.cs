using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Infrastructure.Database;

namespace Weles.Infrastructure.Scanning;

/// <summary>
/// Persists scan observations and correlates them with stable assets. Writes are serialized
/// (SQLite has a single writer) and never cancelled half-way, so partial results survive a stop.
/// </summary>
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

            var asset = await FindAssetAsync(db, ip, result.MacAddress, result.Hostname);
            if (asset is null)
            {
                asset = new Asset { DisplayName = ip, FirstSeenAt = now };
                db.Assets.Add(asset);
            }

            asset.PrimaryIpAddress = ip;
            asset.Hostname = result.Hostname ?? asset.Hostname;
            asset.MacAddress ??= result.MacAddress;
            asset.Vendor = result.Vendor ?? asset.Vendor;
            if (result.Classification.Confidence > 0)
            {
                asset.AssetType = result.Classification.Type;
                asset.ClassificationReasons = host.ClassificationReasons;
            }

            asset.OsFamily = result.Classification.OsFamily ?? asset.OsFamily;
            asset.DisplayName = Truncate(asset.Hostname ?? (asset.Vendor is not null && !asset.Vendor.StartsWith("Adres losowy", StringComparison.Ordinal) ? $"{asset.Vendor} ({ip})" : ip), 255)!;
            asset.LastSeenAt = now;
            asset.NetworkSegmentId = await FindSegmentIdAsync(db, result.Address) ?? asset.NetworkSegmentId;

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

    /// <summary>Creates network segments for every CIDR in the scope (idempotent).</summary>
    public async Task EnsureSegmentsAsync(IEnumerable<(string Cidr, string? Gateway)> segments)
    {
        await _writeLock.WaitAsync();
        try
        {
            await using var db = await contextFactory.CreateDbContextAsync();
            var now = Now;
            // The same CIDR can come from the scope (no gateway) and from a local interface (with gateway) – keep the gateway.
            foreach (var (cidr, gateway) in segments.GroupBy(s => s.Cidr).Select(g => (g.Key, g.Select(x => x.Gateway).FirstOrDefault(x => x is not null))))
            {
                var existing = await db.NetworkSegments.SingleOrDefaultAsync(s => s.Cidr == cidr);
                if (existing is null)
                {
                    db.NetworkSegments.Add(new NetworkSegment { Cidr = cidr, Gateway = gateway, FirstSeenAt = now, LastSeenAt = now });
                }
                else
                {
                    existing.LastSeenAt = now;
                    existing.Gateway ??= gateway;
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
    /// Identity rules: same MAC → same asset. Without a MAC: same IP and no conflicting MAC/hostname.
    /// Otherwise a new asset is created (a different device took the address).
    /// </summary>
    internal static async Task<Asset?> FindAssetAsync(WelesDbContext db, string ip, string? mac, string? hostname)
    {
        if (mac is not null)
        {
            var byMac = await db.Assets.Where(a => a.MacAddress == mac).OrderByDescending(a => a.LastSeenAt).FirstOrDefaultAsync();
            if (byMac is not null) return byMac;
        }

        var byIp = await db.Assets.Where(a => a.PrimaryIpAddress == ip).OrderByDescending(a => a.LastSeenAt).ToListAsync();
        return byIp.FirstOrDefault(a =>
            (a.MacAddress is null || mac is null || a.MacAddress == mac) &&
            (a.Hostname is null || hostname is null || string.Equals(a.Hostname, hostname, StringComparison.OrdinalIgnoreCase)));
    }

    private static async Task<int?> FindSegmentIdAsync(WelesDbContext db, IPAddress address)
    {
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return null;
        var value = Ipv4.ToUInt(address);
        var segments = await db.NetworkSegments.AsNoTracking().Select(s => new { s.Id, s.Cidr }).ToListAsync();
        return segments
            .Select(s => (s.Id, Parsed: TargetParser.TryParse(s.Cidr, out var t, out _) ? t : null))
            .Where(s => s.Parsed?.Ipv4Range is { } r && Ipv4.CidrRange(r.Start, PrefixOf(s.Parsed.Normalized), false).Contains(value))
            .OrderByDescending(s => PrefixOf(s.Parsed!.Normalized))
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
