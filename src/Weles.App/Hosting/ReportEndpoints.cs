using Weles.Infrastructure.Reports;

namespace Weles.App.Hosting;

public static class ReportEndpoints
{
    /// <summary>
    /// Downloads a generated report or export by its record id. The path comes from the database record and is confined
    /// to the reports/exports directory; like every endpoint it is behind <see cref="LocalAccessGuardMiddleware"/>.
    /// </summary>
    public static void MapReportEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/reports/{id:int}/download", async (int id, AuditReportService reports, CancellationToken ct) =>
        {
            var file = await reports.DownloadAsync(id, ct);
            return file is null ? Results.NotFound() : Results.File(file.Path, file.ContentType, file.FileName);
        });
    }
}
