using System.IO.Compression;
using Weles.Infrastructure.Platform;

namespace Weles.App.Hosting;

public static class LogEndpoints
{
    public static void MapLogEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/logs/download", (WelesPaths paths, TimeProvider time, ILoggerFactory loggerFactory) =>
        {
            var logger = loggerFactory.CreateLogger("Weles.Logs");
            var zipPath = Path.Combine(paths.ExportsDirectory, $"weles-logs-{Guid.NewGuid():N}.zip");
            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                foreach (var file in Directory.EnumerateFiles(paths.LogsDirectory, "*.log"))
                {
                    // The active log file is held open by Serilog (shared mode) – copy it with ReadWrite sharing.
                    using var source = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    var entry = zip.CreateEntry(Path.GetFileName(file), CompressionLevel.Optimal);
                    using var target = entry.Open();
                    source.CopyTo(target);
                }
            }

            logger.LogInformation("Log archive exported");
            var stream = new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.None, 81920, FileOptions.DeleteOnClose);
            return Results.File(stream, "application/zip", $"weles-logs-{time.GetUtcNow():yyyyMMdd-HHmmss}.zip");
        });
    }
}
