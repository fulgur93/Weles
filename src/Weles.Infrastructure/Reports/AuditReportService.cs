using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Reports;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Platform;

namespace Weles.Infrastructure.Reports;

public sealed record AuditListItem(int ScanId, DateTime At, string ScopeName, bool IsExternal, bool IsDemo, int Devices, int OpenPorts, double? Posture,
    int Files, bool HasAiSummary);

public sealed record ReportFileItem(int Id, ReportFormat Format, string FileName, long SizeBytes, string Sha256, DateTime CreatedAt, string? Language,
    int? ScanId, int? ImportedAuditId, string AuditTitle, bool Exists);

public sealed record ImportedAuditItem(int Id, string Title, int OriginalScanId, DateTime AuditStartedAt, DateTime ExportedAt, string? ExportedBy,
    int DeviceCount, double? PostureScore, string SourceFileName, string Sha256, DateTime ImportedAt);

/// <summary>A file ready to download: an absolute path inside the reports/exports directory.</summary>
public sealed record ReportDownload(string Path, string ContentType, string FileName);

/// <summary>
/// Reports and audit transfer: stores generated PDF/JSON/ZIP files (reports/ and exports/ in the data directory) with
/// their SHA-256, keeps the history of generated files, imports audits exported by another WELES installation and
/// stores the user's AI summaries of audits. File names are always generated here – never taken from the user.
/// </summary>
public sealed class AuditReportService(
    IDbContextFactory<WelesDbContext> contextFactory,
    WelesPaths paths,
    TimeProvider time,
    ILogger<AuditReportService> logger)
{
    public async Task<IReadOnlyList<AuditListItem>> AuditsAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var scans = await db.Scans.AsNoTracking().Where(s => s.Status == ScanStatus.Completed)
            .Select(s => new
            {
                s.Id, At = s.StartedAt ?? s.CreatedAt, s.ScanTarget!.Name, s.ScanTarget.IsExternal, s.IsDemo, s.HostsAlive, s.OpenPorts,
                Posture = s.RiskScores.Where(r => r.AssetId == null).Select(r => (double?)r.Score).FirstOrDefault()
            })
            .ToListAsync(ct);
        var files = await db.AuditReports.AsNoTracking().Where(r => r.ScanId != null).GroupBy(r => r.ScanId!.Value)
            .Select(g => new { g.Key, Count = g.Count() }).ToDictionaryAsync(x => x.Key, x => x.Count, ct);
        var summaries = (await db.AuditAiSummaries.AsNoTracking().Select(s => s.ScanId).ToListAsync(ct)).ToHashSet();
        return scans.OrderByDescending(s => s.At)
            .Select(s => new AuditListItem(s.Id, s.At, s.Name, s.IsExternal, s.IsDemo, s.HostsAlive, s.OpenPorts, s.Posture,
                files.GetValueOrDefault(s.Id), summaries.Contains(s.Id)))
            .ToList();
    }

    /// <summary>Stores a generated file and records it. <paramref name="scanId"/> or <paramref name="importedAuditId"/> names the audit.</summary>
    public async Task<ReportFileItem> SaveAsync(int? scanId, int? importedAuditId, ReportFormat format, byte[] data, string? language = null, CancellationToken ct = default)
    {
        if ((scanId is null) == (importedAuditId is null)) throw new ArgumentException("Exactly one audit source is required.");
        var now = time.GetUtcNow().UtcDateTime;
        var source = scanId is { } s ? $"audit-{s}" : $"import-{importedAuditId}";
        var suffix = format == ReportFormat.Pdf && language is "en" ? "-en" : "";
        // Local time in the name – the user recognises the file by when they made it.
        var stamp = now.ToLocalTime().ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);
        var fileName = $"weles-{source}-{stamp}{suffix}.{Extension(format)}";
        var directory = DirectoryOf(format);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, fileName);
        // Two files of one audit in the same second: keep both.
        for (var i = 2; File.Exists(path); i++)
        {
            fileName = $"weles-{source}-{stamp}{suffix}-{i}.{Extension(format)}";
            path = Path.Combine(directory, fileName);
        }

        await File.WriteAllBytesAsync(path, data, ct);
        var report = new AuditReport
        {
            ScanId = scanId, ImportedAuditId = importedAuditId, Format = format, FileName = fileName, SizeBytes = data.Length,
            Sha256 = AuditArchive.Sha256Hex(data), CreatedAt = now, Language = format == ReportFormat.Pdf ? language ?? "pl" : null
        };
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        db.AuditReports.Add(report);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Report exported: {Format} for {Source} ({Size} bytes, {File})", format, source, data.Length, fileName);
        return (await ReportsAsync(ct: ct)).First(r => r.Id == report.Id);
    }

    public async Task<IReadOnlyList<ReportFileItem>> ReportsAsync(int take = 100, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var rows = await db.AuditReports.AsNoTracking().OrderByDescending(r => r.CreatedAt).ThenByDescending(r => r.Id).Take(take)
            .Select(r => new { Report = r, ScopeName = r.Scan!.ScanTarget!.Name, ImportedTitle = r.ImportedAudit!.Title })
            .ToListAsync(ct);
        return rows.Select(x =>
        {
            var r = x.Report;
            var title = r.ScanId is { } id ? $"#{id} {x.ScopeName}" : x.ImportedTitle ?? "";
            return new ReportFileItem(r.Id, r.Format, r.FileName, r.SizeBytes, r.Sha256, r.CreatedAt, r.Language, r.ScanId, r.ImportedAuditId, title,
                File.Exists(PathOf(r.Format, r.FileName)));
        }).ToList();
    }

    public async Task<ReportDownload?> DownloadAsync(int reportId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var report = await db.AuditReports.AsNoTracking().SingleOrDefaultAsync(r => r.Id == reportId, ct);
        if (report is null) return null;
        var path = PathOf(report.Format, report.FileName);
        return File.Exists(path) ? new ReportDownload(path, ContentType(report.Format), report.FileName) : null;
    }

    public async Task<bool> DeleteReportAsync(int reportId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var report = await db.AuditReports.SingleOrDefaultAsync(r => r.Id == reportId, ct);
        if (report is null) return false;
        DeleteFile(report);
        db.AuditReports.Remove(report);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Report file deleted: {File}", report.FileName);
        return true;
    }

    /// <summary>Validates and stores an exported audit. Throws <see cref="AuditImportException"/> with the reason for the user.</summary>
    public async Task<ImportedAuditItem> ImportAsync(Stream input, string fileName, CancellationToken ct = default)
    {
        var sourceName = Path.GetFileName(fileName);
        if (sourceName.Length > 200) sourceName = sourceName[..200];
        ImportedDocument imported;
        try
        {
            imported = await AuditArchive.ReadAsync(input, sourceName, ct);
        }
        catch (AuditImportException ex)
        {
            logger.LogWarning("Audit import refused: {Reason}", ex.Message);
            throw;
        }

        await using var db = await contextFactory.CreateDbContextAsync(ct);
        if (await db.ImportedAudits.AsNoTracking().FirstOrDefaultAsync(x => x.Sha256 == imported.Sha256, ct) is { } existing)
        {
            throw new AuditImportException($"Ten audyt został już zaimportowany ({existing.ImportedAt.ToLocalTime():yyyy-MM-dd HH:mm}).");
        }

        var d = imported.Document;
        var title = d.Audit.Network.Contains(d.Audit.ScopeName, StringComparison.Ordinal) ? d.Audit.Network : $"{d.Audit.ScopeName} – {d.Audit.Network}";
        var entity = new ImportedAudit
        {
            Title = title.Length > 300 ? title[..300] : title, OriginalScanId = d.Audit.ScanId, AuditStartedAt = d.Audit.StartedAt, ExportedAt = d.ExportedAt,
            ExportedBy = d.GeneratedBy.Length > 100 ? d.GeneratedBy[..100] : d.GeneratedBy, SchemaVersion = d.SchemaVersion, DeviceCount = d.Devices.Count,
            PostureScore = d.Posture?.Score, SourceFileName = sourceName, Sha256 = imported.Sha256, ImportedAt = time.GetUtcNow().UtcDateTime,
            DocumentJson = imported.Json
        };
        db.ImportedAudits.Add(entity);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Audit imported: #{Id} (original scan #{Scan}, {Devices} devices, {File})", entity.Id, d.Audit.ScanId, d.Devices.Count, sourceName);
        return Item(entity);
    }

    public async Task<IReadOnlyList<ImportedAuditItem>> ImportedAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var rows = await db.ImportedAudits.AsNoTracking()
            .Select(x => new ImportedAudit
            {
                Id = x.Id, Title = x.Title, OriginalScanId = x.OriginalScanId, AuditStartedAt = x.AuditStartedAt, ExportedAt = x.ExportedAt, ExportedBy = x.ExportedBy,
                DeviceCount = x.DeviceCount, PostureScore = x.PostureScore, SourceFileName = x.SourceFileName, Sha256 = x.Sha256, ImportedAt = x.ImportedAt,
                DocumentJson = ""
            })
            .ToListAsync(ct);
        return rows.OrderByDescending(x => x.ImportedAt).Select(Item).ToList();
    }

    public async Task<(ImportedAuditItem Info, AuditDocument Document)?> ImportedDocumentAsync(int id, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var entity = await db.ImportedAudits.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        if (entity is null) return null;
        // Stored only after validation; parsed again defensively.
        var document = JsonSerializer.Deserialize<AuditDocument>(entity.DocumentJson, AuditJson.Options);
        if (document is null) return null;
        AuditArchive.Validate(document);
        return (Item(entity), document);
    }

    public async Task<bool> DeleteImportedAsync(int id, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var entity = await db.ImportedAudits.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (entity is null) return false;
        foreach (var report in await db.AuditReports.Where(r => r.ImportedAuditId == id).ToListAsync(ct)) DeleteFile(report);
        db.ImportedAudits.Remove(entity);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Imported audit #{Id} deleted", id);
        return true;
    }

    public async Task<AuditAiSummary?> AiSummaryAsync(int scanId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        return await db.AuditAiSummaries.AsNoTracking().SingleOrDefaultAsync(s => s.ScanId == scanId, ct);
    }

    /// <summary>Stores (or replaces) the AI summary of an audit.</summary>
    public async Task SaveAiSummaryAsync(int scanId, string text, string? model, string language, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var summary = await db.AuditAiSummaries.SingleOrDefaultAsync(s => s.ScanId == scanId, ct);
        if (summary is null)
        {
            summary = new AuditAiSummary { ScanId = scanId, Text = text };
            db.AuditAiSummaries.Add(summary);
        }

        summary.Text = text.Length > 20_000 ? text[..20_000] : text;
        summary.Model = model;
        summary.Language = language == "en" ? "en" : "pl";
        summary.CreatedAt = time.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteAiSummaryAsync(int scanId, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        await db.AuditAiSummaries.Where(s => s.ScanId == scanId).ExecuteDeleteAsync(ct);
    }

    public static string Extension(ReportFormat format) => format switch
    {
        ReportFormat.Pdf => "pdf",
        ReportFormat.Json => "json",
        _ => "zip"
    };

    public static string ContentType(ReportFormat format) => format switch
    {
        ReportFormat.Pdf => "application/pdf",
        ReportFormat.Json => "application/json",
        _ => "application/zip"
    };

    private string DirectoryOf(ReportFormat format) => format == ReportFormat.Pdf ? paths.ReportsDirectory : paths.ExportsDirectory;

    /// <summary>File names come from <see cref="SaveAsync"/>; a name that is not a bare file name never leaves the directory.</summary>
    private string PathOf(ReportFormat format, string fileName) =>
        Path.Combine(DirectoryOf(format), Path.GetFileName(fileName) == fileName ? fileName : "invalid");

    private void DeleteFile(AuditReport report)
    {
        try
        {
            File.Delete(PathOf(report.Format, report.FileName));
        }
        catch (IOException ex)
        {
            logger.LogWarning("Report file {File} could not be deleted: {Error}", report.FileName, ex.Message);
        }
    }

    private static ImportedAuditItem Item(ImportedAudit x) => new(x.Id, x.Title, x.OriginalScanId, x.AuditStartedAt, x.ExportedAt, x.ExportedBy,
        x.DeviceCount, x.PostureScore, x.SourceFileName, x.Sha256, x.ImportedAt);
}
