using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Models;
using Weles.Core.Networking;
using Weles.Core.Rules;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Scanning;

namespace Weles.Infrastructure.Import;

public sealed class ScanImportException(string message) : Exception(message);

/// <param name="Skipped">Hosts outside the chosen scope or with invalid data.</param>
public sealed record ScanImportResult(int ScanId, int ScopeId, string Format, int Hosts, int Ports, int Skipped, IReadOnlyList<string> Warnings);

/// <summary>One imported host before it becomes a <see cref="HostScanResult"/>.</summary>
public sealed record ImportedHost(string Ip, string? Hostname, string? Mac, string? Vendor, List<ImportedPort> Ports, string? Os = null);

public sealed record ImportedPort(int Port, TransportProtocol Protocol, string? Service, string? Product, string? Version, string? Cpe, string? Banner, int? Confidence, bool Tls);

/// <summary>
/// Scan results from files – nmap XML (<c>nmap -oX</c>), CSV and JSON (the WELES export format, also flat rows). They are
/// stored as a completed scan (trigger Import) of a scope, so comparisons, vulnerability matching, risk and reports
/// work exactly as for WELES's own scans. Nothing is sent to the network. Files are untrusted: size limits, no DTD or
/// external entities in XML, every address and port validated, hosts outside the chosen scope dropped.
/// </summary>
public sealed partial class ScanImportService(
    IDbContextFactory<WelesDbContext> contextFactory,
    ScanResultWriter writer,
    ScanPostProcessor postProcessor,
    OuiDatabase oui,
    TimeProvider time,
    ILogger<ScanImportService> logger)
{
    public const long MaxFileBytes = 50L * 1024 * 1024;
    public const int MaxHosts = 65_536;
    private const int MaxPortsPerHost = 4096;

    /// <param name="scopeId">Existing scope to attach the results to (hosts outside it are dropped); null – a new scope "Import – file" is created.</param>
    public async Task<ScanImportResult> ImportAsync(Stream input, string fileName, int? scopeId, CancellationToken ct = default)
    {
        var data = await ReadLimitedAsync(input, ct);
        var text = Encoding.UTF8.GetString(data).TrimStart('﻿');
        var (format, hosts, started) = Parse(text, fileName);
        if (hosts.Count == 0) throw new ScanImportException("Plik nie zawiera żadnego hosta.");
        if (hosts.Count > MaxHosts) throw new ScanImportException($"Plik zawiera więcej niż {MaxHosts} hostów.");

        var warnings = new List<string>();
        var valid = new List<(IPAddress Address, ImportedHost Host)>();
        foreach (var h in hosts)
        {
            if (!IPAddress.TryParse(h.Ip, out var ip)) { warnings.Add($"Pominięto nieprawidłowy adres „{Short(h.Ip)}”."); continue; }
            valid.Add((ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip, h));
        }

        valid = valid.GroupBy(v => v.Address).Select(g => (g.Key, g.First().Host with { Ports = g.SelectMany(x => x.Host.Ports).DistinctBy(p => (p.Port, p.Protocol)).ToList() })).ToList();

        await using var db = await contextFactory.CreateDbContextAsync(ct);
        ScanTarget scope;
        if (scopeId is { } id)
        {
            scope = await db.ScanTargets.Include(t => t.Entries).SingleOrDefaultAsync(t => t.Id == id, ct) ?? throw new ScanImportException("Wybrany zakres nie istnieje.");
            // Membership only – nothing is scanned, so reserved/documentation ranges a scan would skip still count.
            var coverage = ScopeCoverage.FromSnapshot(JsonSerializer.Serialize(scope.Entries.Select(e => new { e.Value, e.IsExclusion })));
            var outside = valid.Count(v => !coverage.Covers(v.Address));
            if (outside > 0) warnings.Add($"Pominięto {outside} hostów spoza zakresu „{scope.Name}”.");
            valid = valid.Where(v => coverage.Covers(v.Address)).ToList();
        }
        else
        {
            var now = time.GetUtcNow().UtcDateTime;
            var name = $"Import – {Path.GetFileName(fileName)}";
            if (name.Length > 200) name = name[..200];
            if (await db.ScanTargets.AnyAsync(t => t.Name == name, ct)) name = $"{name[..Math.Min(name.Length, 180)]} ({now:yyyy-MM-dd HH:mm:ss})";
            scope = new ScanTarget
            {
                Name = name, Description = "Zakres utworzony z importu wyników – WELES nie skanował tych adresów.",
                CreatedAt = now, UpdatedAt = now, AllowPublicAddresses = valid.Any(v => AddressClassifier.IsPublic(v.Address)),
                Entries = valid.Select(v => new ScanTargetEntry { Value = v.Address.ToString(), Kind = ScanTargetEntryKind.IpAddress }).ToList()
            };
            db.ScanTargets.Add(scope);
            await db.SaveChangesAsync(ct);
        }

        if (valid.Count == 0) throw new ScanImportException("Żaden host z pliku nie należy do wybranego zakresu.");
        var startedAt = started ?? time.GetUtcNow().UtcDateTime;
        var scan = new Scan
        {
            ScanTargetId = scope.Id, Status = ScanStatus.Running, Trigger = ScanTrigger.Import, PortSpecification = "import",
            CreatedAt = time.GetUtcNow().UtcDateTime, StartedAt = startedAt, HostsTargeted = valid.Count, HostsProbed = valid.Count,
            ScopeSnapshot = JsonSerializer.Serialize(scope.Entries.Select(e => new { e.Value, e.IsExclusion }))
        };
        db.Scans.Add(scan);
        await db.SaveChangesAsync(ct);

        var ports = 0;
        foreach (var (address, host) in valid)
        {
            var result = ToResult(address, host);
            ports += result.OpenPorts.Count;
            await writer.SaveHostAsync(scan.Id, result);
        }

        scan.Status = ScanStatus.Completed;
        scan.CompletedAt = time.GetUtcNow().UtcDateTime;
        scan.PortCount = valid.SelectMany(v => v.Host.Ports).Select(p => p.Port).Distinct().Count();
        await db.Scans.Where(s => s.Id == scan.Id).ExecuteUpdateAsync(u => u.SetProperty(s => s.Status, ScanStatus.Completed)
            .SetProperty(s => s.CompletedAt, scan.CompletedAt).SetProperty(s => s.PortCount, scan.PortCount), ct);
        var skipped = hosts.Count - valid.Count;
        await writer.AddEventAsync(scan.Id, ScanEventLevel.Info,
            $"Zaimportowano wyniki z pliku „{Short(Path.GetFileName(fileName))}” ({format}): {valid.Count} hostów, {ports} otwartych portów. WELES nie wysłał żadnego ruchu.");
        foreach (var w in warnings.Take(10)) await writer.AddEventAsync(scan.Id, ScanEventLevel.Warning, w);
        await postProcessor.RunAsync(scan.Id, ct);
        logger.LogInformation("Imported {Format} results into scan {ScanId} ({Hosts} hosts, {Ports} ports, {Skipped} skipped)", format, scan.Id, valid.Count, ports, skipped);
        return new ScanImportResult(scan.Id, scope.Id, format, valid.Count, ports, skipped, warnings);
    }

    internal static (string Format, List<ImportedHost> Hosts, DateTime? Started) Parse(string text, string fileName)
    {
        var trimmed = text.TrimStart();
        if (trimmed.StartsWith('<')) return ("nmap XML", ParseNmap(text, out var started), started);
        if (trimmed.StartsWith('{') || trimmed.StartsWith('[') || fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) return ("JSON", ParseJson(text), null);
        return ("CSV", ParseCsv(text), null);
    }

    /// <summary>nmap XML: DTD processing prohibited and no resolver – no external entities, no network access.</summary>
    private static List<ImportedHost> ParseNmap(string xml, out DateTime? started)
    {
        started = null;
        var doc = new XmlDocument { XmlResolver = null };
        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, MaxCharactersFromEntities = 0 });
            doc.Load(reader);
        }
        catch (XmlException ex)
        {
            throw new ScanImportException($"Nieprawidłowy XML: {ex.Message}");
        }

        var root = doc.DocumentElement;
        if (root?.Name != "nmaprun") throw new ScanImportException("To nie jest wynik nmap (brak elementu nmaprun) – użyj nmap -oX.");
        if (long.TryParse(root.GetAttribute("start"), out var unix)) started = DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime;
        var hosts = new List<ImportedHost>();
        foreach (XmlElement host in root.SelectNodes("host")!)
        {
            if (host.SelectSingleNode("status") is XmlElement status && status.GetAttribute("state") != "up") continue;
            var ip = host.SelectNodes("address")!.Cast<XmlElement>().FirstOrDefault(a => a.GetAttribute("addrtype") is "ipv4" or "ipv6")?.GetAttribute("addr");
            if (ip is null) continue;
            var macEl = host.SelectNodes("address")!.Cast<XmlElement>().FirstOrDefault(a => a.GetAttribute("addrtype") == "mac");
            var hostname = (host.SelectSingleNode("hostnames/hostname") as XmlElement)?.GetAttribute("name");
            var ports = new List<ImportedPort>();
            foreach (XmlElement port in host.SelectNodes("ports/port")!)
            {
                if ((port.SelectSingleNode("state") as XmlElement)?.GetAttribute("state") != "open") continue;
                if (!int.TryParse(port.GetAttribute("portid"), out var number)) continue;
                var svc = port.SelectSingleNode("service") as XmlElement;
                var product = Empty(svc?.GetAttribute("product"));
                var extra = Empty(svc?.GetAttribute("extrainfo"));
                ports.Add(new ImportedPort(number, port.GetAttribute("protocol") == "udp" ? TransportProtocol.Udp : TransportProtocol.Tcp,
                    Empty(svc?.GetAttribute("name")), product, Empty(svc?.GetAttribute("version")), Cpe23(svc?.SelectSingleNode("cpe")?.InnerText),
                    extra is null ? null : $"{product} {extra}".Trim(), int.TryParse(svc?.GetAttribute("conf"), out var conf) ? conf * 10 : null,
                    svc?.GetAttribute("tunnel") == "ssl"));
            }

            var os = (host.SelectSingleNode("os/osmatch") as XmlElement)?.GetAttribute("name");
            hosts.Add(new ImportedHost(ip, Empty(hostname), Empty(macEl?.GetAttribute("addr")), Empty(macEl?.GetAttribute("vendor")), ports, Empty(os)));
        }

        return hosts;
    }

    private sealed record JsonPort(int Port, string? Protocol, string? Service, string? Product, string? Version, string? Cpe, string? Banner, int? Confidence, bool? Tls);

    private sealed record JsonHost(string? Ip, string? Hostname, string? Mac, string? Vendor, string? Os, List<JsonPort>? Ports,
        // flat-row form (one row per port, like the CSV)
        int? Port, string? Protocol, string? Service, string? Product, string? Version, string? Cpe, string? Banner);

    private sealed record JsonDocumentShape(List<JsonHost>? Hosts);

    private static readonly JsonSerializerOptions ImportJson = new(JsonSerializerDefaults.Web) { MaxDepth = 16, AllowTrailingCommas = true, ReadCommentHandling = JsonCommentHandling.Skip };

    private static List<ImportedHost> ParseJson(string json)
    {
        List<JsonHost>? rows;
        try
        {
            rows = json.TrimStart().StartsWith('[')
                ? JsonSerializer.Deserialize<List<JsonHost>>(json, ImportJson)
                : JsonSerializer.Deserialize<JsonDocumentShape>(json, ImportJson)?.Hosts;
        }
        catch (JsonException ex)
        {
            throw new ScanImportException($"Nieprawidłowy JSON: {ex.Message}");
        }

        if (rows is null) throw new ScanImportException("JSON nie zawiera listy hostów (tablica albo obiekt z polem hosts).");
        return rows.Where(r => r?.Ip is not null).GroupBy(r => r.Ip!.Trim()).Select(g =>
        {
            var first = g.First();
            var ports = g.SelectMany(r => r.Ports ?? (r.Port is { } p ? [new JsonPort(p, r.Protocol, r.Service, r.Product, r.Version, r.Cpe, r.Banner, null, null)] : []))
                .Select(p => new ImportedPort(p.Port, string.Equals(p.Protocol, "udp", StringComparison.OrdinalIgnoreCase) ? TransportProtocol.Udp : TransportProtocol.Tcp,
                    Empty(p.Service), Empty(p.Product), Empty(p.Version), Cpe23(p.Cpe), Empty(p.Banner), p.Confidence, p.Tls ?? false))
                .ToList();
            return new ImportedHost(g.Key, Empty(first.Hostname), Empty(first.Mac), Empty(first.Vendor), ports, Empty(first.Os));
        }).ToList();
    }

    /// <summary>CSV with a header: ip (required), port, protocol, service, product, version, cpe, banner, hostname, mac, vendor.</summary>
    private static List<ImportedHost> ParseCsv(string text)
    {
        var lines = text.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList();
        if (lines.Count == 0) throw new ScanImportException("Pusty plik CSV.");
        var header = SplitCsv(lines[0]).Select(h => h.Trim().ToLowerInvariant()).ToList();
        var ipColumn = header.FindIndex(h => h is "ip" or "address" or "host" or "ip_address");
        if (ipColumn < 0) throw new ScanImportException("CSV musi mieć nagłówek z kolumną ip (oraz opcjonalnie port, protocol, service, product, version, cpe, banner, hostname, mac, vendor).");
        string? Col(IReadOnlyList<string> cells, string name) => header.IndexOf(name) is >= 0 and var i && i < cells.Count ? Empty(cells[i]) : null;

        var hosts = new Dictionary<string, ImportedHost>();
        foreach (var line in lines.Skip(1))
        {
            var cells = SplitCsv(line);
            if (ipColumn >= cells.Count || Empty(cells[ipColumn]) is not { } ip) continue;
            if (!hosts.TryGetValue(ip, out var host))
            {
                host = new ImportedHost(ip, Col(cells, "hostname"), Col(cells, "mac"), Col(cells, "vendor"), []);
                hosts[ip] = host;
            }

            if (int.TryParse(Col(cells, "port"), out var port))
            {
                host.Ports.Add(new ImportedPort(port, string.Equals(Col(cells, "protocol"), "udp", StringComparison.OrdinalIgnoreCase) ? TransportProtocol.Udp : TransportProtocol.Tcp,
                    Col(cells, "service"), Col(cells, "product"), Col(cells, "version"), Cpe23(Col(cells, "cpe")), Col(cells, "banner"), null, false));
            }
        }

        return hosts.Values.ToList();
    }

    internal static List<string> SplitCsv(string line)
    {
        var cells = new List<string>();
        var sb = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                else if (c == '"') quoted = false;
                else sb.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c is ',' or ';' or '\t') { cells.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }

        cells.Add(sb.ToString());
        // A leading apostrophe added against CSV injection (WELES export) is not part of the value.
        return cells.Select(c => c.StartsWith('\'') && c.Length > 1 && c[1] is '=' or '+' or '-' or '@' ? c[1..] : c).ToList();
    }

    private HostScanResult ToResult(IPAddress address, ImportedHost host)
    {
        var mac = host.Mac is { } m && MacPattern().IsMatch(m) ? m.ToLowerInvariant().Replace('-', ':') : null;
        var vendor = oui.Lookup(mac) ?? Clean(host.Vendor, 128);
        var ports = host.Ports.Where(p => p.Port is >= 1 and <= 65535).DistinctBy(p => (p.Port, p.Protocol)).Take(MaxPortsPerHost)
            .Select(p =>
            {
                var hint = ServiceIdentification.FromPortOnly(p.Port);
                var product = Clean(p.Product, 128);
                var id = new ServiceIdentification
                {
                    ServiceName = Clean(p.Tls && p.Service is { } s && !s.StartsWith("ssl") ? $"ssl/{s}" : p.Service, 64) ?? hint.ServiceName,
                    Product = product, Version = Clean(p.Version, 128),
                    Vendor = product is null ? null : ProductCatalog.Find(product)?.CpeVendor,
                    Cpe = Clean(p.Cpe, 256) ?? (product is null ? null : ProductCatalog.Cpe(product, p.Version)),
                    Banner = Clean(p.Banner, 1024), Confidence = Math.Clamp(p.Confidence ?? (product is null ? 50 : 80), 0, 100),
                    Method = "import", IsTls = p.Tls
                };
                return new PortScanResult(p.Port, "import", new ServiceProbeResult(id, null));
            }).ToList();
        var hostname = Clean(host.Hostname, 255);
        var classification = AssetClassifier.Classify(new HostEvidence(ports.Select(p => p.Port).ToList(), ports.Select(p => p.Service!.Identification).ToList(),
            vendor, null, false, hostname));
        if (host.Os is { } os && classification.OsFamily is null) classification = classification with { OsFamily = Clean(os, 64) };
        return new HostScanResult(address, DiscoveryMethod.None, null, null, hostname, mac, vendor, false, classification, ports);
    }

    /// <summary>"cpe:/a:openbsd:openssh:8.9p1" (nmap, CPE 2.2) → "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*".</summary>
    internal static string? Cpe23(string? cpe)
    {
        cpe = Empty(cpe);
        if (cpe is null || cpe.StartsWith("cpe:2.3:", StringComparison.Ordinal)) return cpe;
        if (!cpe.StartsWith("cpe:/", StringComparison.Ordinal)) return null;
        var parts = cpe[5..].Split(':');
        var fields = parts.Concat(Enumerable.Repeat("*", Math.Max(0, 11 - parts.Length))).Take(11);
        return "cpe:2.3:" + string.Join(':', fields.Select(f => f.Length == 0 ? "*" : f));
    }

    private static async Task<byte[]> ReadLimitedAsync(Stream input, CancellationToken ct)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await input.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + read > MaxFileBytes) throw new ScanImportException("Plik jest większy niż 50 MB.");
            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    private static string? Empty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string? Clean(string? value, int max)
    {
        value = Empty(value);
        if (value is null) return null;
        var cleaned = new string(value.Select(c => char.IsControl(c) && c is not '\n' ? ' ' : c).ToArray());
        return cleaned.Length > max ? cleaned[..max] : cleaned;
    }

    private static string Short(string value) => value.Length > 80 ? value[..80] + "…" : value;

    [GeneratedRegex("^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")]
    private static partial Regex MacPattern();
}
