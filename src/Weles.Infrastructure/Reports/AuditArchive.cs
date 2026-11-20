using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Weles.Core.Reports;

namespace Weles.Infrastructure.Reports;

/// <summary>Why an imported file was refused – the message is shown to the user.</summary>
public sealed class AuditImportException(string message) : Exception(message);

/// <summary>An audit read from a file, with the SHA-256 of its JSON (the same audit is not imported twice).</summary>
public sealed record ImportedDocument(AuditDocument Document, string Json, string Sha256);

/// <summary>
/// The export format. A ZIP holds <c>manifest.json</c> (file list with SHA-256), <c>audit.json</c> (the
/// <see cref="AuditDocument"/>) and optionally <c>report.pdf</c>; a plain <c>.json</c> file is the audit document alone.
/// Imported files are untrusted: nothing is ever extracted to disk, only the three known entry names are accepted, every
/// entry is read with a hard size limit (the sizes declared in the archive are not trusted), hashes from the manifest
/// must match, and the document must pass the schema checks below.
/// </summary>
public static class AuditArchive
{
    public const string ManifestEntry = "manifest.json";
    public const string AuditEntry = "audit.json";
    public const string ReportEntry = "report.pdf";
    public const string ArchiveFormat = "weles-audit-archive";

    public const long MaxImportBytes = 50L * 1024 * 1024;
    public const int MaxAuditJsonBytes = 20 * 1024 * 1024;
    private const int MaxManifestBytes = 64 * 1024;
    private const int MaxReportBytes = 40 * 1024 * 1024;
    private const int MaxEntries = 8;

    // Schema limits – far above anything a real scan produces (a /16 scope is the largest WELES accepts).
    private const int MaxDevices = 70_000;
    private const int MaxListItems = 5_000;
    private const int MaxTextLength = 20_000;

    private sealed record ManifestFile(string Path, string Sha256, long Size);

    private sealed record Manifest(string Format, int SchemaVersion, DateTime ExportedAt, string GeneratedBy, IReadOnlyList<ManifestFile> Files);

    public static byte[] ToJson(AuditDocument document) => JsonSerializer.SerializeToUtf8Bytes(document, AuditJson.Options);

    /// <summary>Writes the ZIP export; <paramref name="pdf"/> adds the PDF report for people without WELES.</summary>
    public static void WriteZip(Stream output, AuditDocument document, byte[]? pdf)
    {
        var json = ToJson(document);
        var files = new List<(string Name, byte[] Data)> { (AuditEntry, json) };
        if (pdf is not null) files.Add((ReportEntry, pdf));
        var manifest = new Manifest(ArchiveFormat, AuditDocument.CurrentSchemaVersion, document.ExportedAt, document.GeneratedBy,
            files.Select(f => new ManifestFile(f.Name, Sha256Hex(f.Data), f.Data.Length)).ToList());

        using var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true);
        void Add(string name, byte[] data)
        {
            var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
            entry.LastWriteTime = new DateTimeOffset(document.ExportedAt, TimeSpan.Zero);
            using var stream = entry.Open();
            stream.Write(data);
        }

        Add(ManifestEntry, JsonSerializer.SerializeToUtf8Bytes(manifest, AuditJson.Options));
        foreach (var (name, data) in files) Add(name, data);
    }

    /// <summary>Reads and validates a ZIP or JSON export. Throws <see cref="AuditImportException"/> with the reason.</summary>
    public static async Task<ImportedDocument> ReadAsync(Stream input, string fileName, CancellationToken ct = default)
    {
        // Read asynchronously with a hard limit – browser uploads support async reads only, and the declared size is not trusted.
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await input.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + read > MaxImportBytes) throw new AuditImportException("Plik jest większy niż 50 MB.");
            buffer.Write(chunk, 0, read);
        }

        return Read(buffer.ToArray(), fileName);
    }

    public static ImportedDocument Read(byte[] data, string fileName)
    {
        if (data.Length >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 3 && data[3] == 4) return ReadZip(data);
        if (Path.GetExtension(fileName).Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            throw new AuditImportException("Plik ma rozszerzenie .zip, ale nie jest archiwum ZIP.");
        }

        if (data.Length > MaxAuditJsonBytes) throw new AuditImportException("Plik JSON audytu jest większy niż 20 MB.");
        return Parse(data);
    }

    private static ImportedDocument ReadZip(byte[] data)
    {
        Dictionary<string, byte[]> entries = new(StringComparer.Ordinal);
        try
        {
            using var zip = new ZipArchive(new MemoryStream(data, writable: false), ZipArchiveMode.Read);
            if (zip.Entries.Count > MaxEntries) throw new AuditImportException("Archiwum zawiera zbyt wiele plików – to nie jest eksport WELES.");
            foreach (var entry in zip.Entries)
            {
                // Only the known names, without directories – nothing is ever written to disk, so paths cannot escape anyway.
                var limit = entry.FullName switch
                {
                    ManifestEntry => MaxManifestBytes,
                    AuditEntry => MaxAuditJsonBytes,
                    ReportEntry => MaxReportBytes,
                    _ => throw new AuditImportException($"Nieoczekiwany plik w archiwum: „{Printable(entry.FullName)}” – to nie jest eksport WELES.")
                };
                if (entries.ContainsKey(entry.FullName)) throw new AuditImportException($"Plik „{entry.FullName}” występuje w archiwum dwa razy.");
                if (entry.Length > limit) throw new AuditImportException($"Plik „{entry.FullName}” w archiwum jest za duży.");
                using var stream = entry.Open();
                entries[entry.FullName] = ReadLimited(stream, limit, $"Plik „{entry.FullName}” w archiwum jest za duży.");
            }
        }
        catch (InvalidDataException)
        {
            throw new AuditImportException("Archiwum ZIP jest uszkodzone.");
        }

        if (!entries.TryGetValue(ManifestEntry, out var manifestBytes) || !entries.TryGetValue(AuditEntry, out var json))
        {
            throw new AuditImportException("W archiwum brakuje manifest.json lub audit.json – to nie jest eksport WELES.");
        }

        Manifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<Manifest>(manifestBytes, AuditJson.Options);
        }
        catch (JsonException)
        {
            throw new AuditImportException("Plik manifest.json jest nieprawidłowy.");
        }

        if (manifest is null || manifest.Format != ArchiveFormat || manifest.Files is null)
        {
            throw new AuditImportException("Plik manifest.json nie opisuje eksportu WELES.");
        }

        foreach (var (name, bytes) in entries.Where(e => e.Key != ManifestEntry))
        {
            var listed = manifest.Files.FirstOrDefault(f => f?.Path == name);
            if (listed is null || !string.Equals(listed.Sha256, Sha256Hex(bytes), StringComparison.OrdinalIgnoreCase) || listed.Size != bytes.Length)
            {
                throw new AuditImportException($"Suma kontrolna pliku „{name}” nie zgadza się z manifestem – archiwum zostało zmienione lub uszkodzone.");
            }
        }

        return Parse(json);
    }

    private static ImportedDocument Parse(byte[] json)
    {
        AuditDocument? document;
        try
        {
            document = JsonSerializer.Deserialize<AuditDocument>(json, AuditJson.Options);
        }
        catch (JsonException ex)
        {
            throw new AuditImportException($"Plik audytu nie jest poprawnym JSON-em WELES ({ex.Path ?? "?"}).");
        }

        if (document is null) throw new AuditImportException("Plik audytu jest pusty.");
        Validate(document);
        return new ImportedDocument(document, Encoding.UTF8.GetString(json), Sha256Hex(json));
    }

    /// <summary>Schema checks: required parts present, supported version, sane sizes. A refused file is never partially imported.</summary>
    internal static void Validate(AuditDocument d)
    {
        if (d.Format != AuditDocument.FormatName) throw new AuditImportException("To nie jest plik audytu WELES (brak pola format = weles-audit).");
        if (d.SchemaVersion < 1 || d.SchemaVersion > AuditDocument.CurrentSchemaVersion)
        {
            throw new AuditImportException($"Wersja formatu {d.SchemaVersion} nie jest obsługiwana (obsługiwana: {AuditDocument.CurrentSchemaVersion}) – zaktualizuj WELES.");
        }

        Require(d.Audit is not null && d.Devices is not null && d.Recommendations is not null, "audit, devices, recommendations");
        var a = d.Audit!;
        Require(a.ScopeName is not null && a.Scope is not null && a.Network is not null && a.PortSpecification is not null, "audit");
        Text(a.ScopeName); Text(a.Network); Text(a.PortSpecification); Text(d.GeneratedBy);
        Count(a.Scope!.Count); foreach (var s in a.Scope) Text(s);

        if (d.Devices!.Count > MaxDevices) throw new AuditImportException("Plik audytu zawiera zbyt wiele urządzeń.");
        foreach (var device in d.Devices)
        {
            Require(device is not null && device.Name is not null && device.Services is not null && device.Vulnerabilities is not null
                    && device.Findings is not null && device.RiskFactors is not null, "devices");
            Text(device!.Name); Text(device.Ip); Text(device.Hostname); Text(device.Mac); Text(device.Vendor); Text(device.Os); Text(device.Model);
            Score(device.RiskScore);
            Count(device.Services!.Count); Count(device.Vulnerabilities!.Count); Count(device.Findings!.Count); Count(device.RiskFactors!.Count);
            foreach (var s in device.Services)
            {
                Require(s is not null && s.Port is >= 1 and <= 65535, "services");
                Text(s!.Name); Text(s.Product); Text(s.Version);
                if (s.Certificate is { } c) { Text(c.Subject); Text(c.Issuer); Text(c.TlsProtocol); }
            }

            foreach (var v in device.Vulnerabilities)
            {
                Require(v is not null && v.CveId is not null, "vulnerabilities");
                Text(v!.CveId); Text(v.Title); Text(v.MatchReason); Text(v.Product); Text(v.Version);
            }

            foreach (var f in device.Findings)
            {
                Require(f is not null && f.RuleId is not null && f.Title is not null, "findings");
                Text(f!.RuleId); Text(f.Title); Text(f.Evidence); Text(f.Recommendation); Score(f.Score);
            }

            Factors(device.RiskFactors);
        }

        Count(d.Recommendations!.Count);
        foreach (var r in d.Recommendations)
        {
            Require(r is not null && r.Device is not null && r.Title is not null && r.Recommendation is not null && r.CveIds is not null, "recommendations");
            Text(r!.Device); Text(r.Ip); Text(r.Title); Text(r.Recommendation); Score(r.Priority);
            Count(r.CveIds!.Count); foreach (var cve in r.CveIds) Text(cve);
        }

        if (d.Posture is { } p)
        {
            Require(p.Factors is not null, "posture");
            Score(p.Score); Score(p.Previous); Factors(p.Factors!);
        }

        if (d.Changes is { } ch)
        {
            Require(ch.Items is not null, "changes");
            Count(ch.Items!.Count);
            foreach (var i in ch.Items) { Require(i is not null && i.Device is not null && i.Description is not null, "changes"); Text(i!.Device); Text(i.Description); }
        }

        if (d.AiSummary is { } ai) { Require(ai.Text is not null, "aiSummary"); Text(ai.Text); Text(ai.Model); Text(ai.Language); }
    }

    private static void Factors(IReadOnlyList<Core.Risk.RiskFactor> factors)
    {
        Count(factors.Count);
        foreach (var f in factors) { Require(f is not null && f.Kind is not null && f.Text is not null, "factors"); Text(f!.Kind); Text(f.Text); }
    }

    private static void Require(bool condition, string part)
    {
        if (!condition) throw new AuditImportException($"Plik audytu jest niekompletny (brak wymaganych danych: {part}).");
    }

    private static void Text(string? value)
    {
        if (value is { Length: > MaxTextLength }) throw new AuditImportException("Plik audytu zawiera zbyt długi tekst.");
    }

    private static void Count(int count)
    {
        if (count > MaxListItems) throw new AuditImportException("Plik audytu zawiera zbyt długą listę.");
    }

    private static void Score(double? value)
    {
        if (value is { } v && (double.IsNaN(v) || v < 0 || v > 100)) throw new AuditImportException("Plik audytu zawiera ocenę spoza zakresu 0–100.");
    }

    private static byte[] ReadLimited(Stream stream, long limit, string tooLarge)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = stream.Read(chunk, 0, chunk.Length)) > 0)
        {
            if (buffer.Length + read > limit) throw new AuditImportException(tooLarge);
            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    public static string Sha256Hex(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    private static string Printable(string name) => new(name.Take(80).Select(c => char.IsControl(c) ? '?' : c).ToArray());
}
