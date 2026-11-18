using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Weles.Infrastructure.Database;

public sealed record DatabaseInfo(string FilePath, long SizeBytes, IReadOnlyList<string> AppliedMigrations, IReadOnlyList<string> PendingMigrations, string SqliteVersion);

public sealed class DatabaseInfoService(IDbContextFactory<WelesDbContext> contextFactory)
{
    public async Task<DatabaseInfo> GetInfoAsync(CancellationToken cancellationToken = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(cancellationToken);
        var path = new SqliteConnectionStringBuilder(db.Database.GetConnectionString()).DataSource;
        var applied = (await db.Database.GetAppliedMigrationsAsync(cancellationToken)).ToList();
        var pending = (await db.Database.GetPendingMigrationsAsync(cancellationToken)).ToList();
        var version = await db.Database.SqlQueryRaw<string>("SELECT sqlite_version() AS Value").SingleAsync(cancellationToken);
        var size = File.Exists(path) ? new FileInfo(path).Length : 0;
        return new DatabaseInfo(path, size, applied, pending, version);
    }
}
