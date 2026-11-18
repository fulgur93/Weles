using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Weles.Infrastructure.Database;

public sealed class DatabaseInitializer(IDbContextFactory<WelesDbContext> contextFactory, ILogger<DatabaseInitializer> logger)
{
    /// <summary>Creates the database if needed, applies pending migrations and enables WAL mode.</summary>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(cancellationToken);

        var pending = (await db.Database.GetPendingMigrationsAsync(cancellationToken)).ToList();
        if (pending.Count > 0)
        {
            logger.LogInformation("Applying {Count} database migration(s): {Migrations}", pending.Count, string.Join(", ", pending));
        }

        await db.Database.MigrateAsync(cancellationToken);

        // WAL lets the UI read while the scanner writes. The setting is persistent in the database file.
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", cancellationToken);

        var dataSource = new SqliteConnectionStringBuilder(db.Database.GetConnectionString()).DataSource;
        logger.LogInformation("Database ready: {DataSource}", dataSource);
    }
}
