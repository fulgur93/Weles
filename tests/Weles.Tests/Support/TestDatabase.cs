using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Weles.Infrastructure.Database;

namespace Weles.Tests.Support;

/// <summary>A real SQLite database file in a temp directory, migrated exactly like in production.</summary>
public sealed class TestDatabase : IDbContextFactory<WelesDbContext>, IAsyncDisposable
{
    private readonly DbContextOptions<WelesDbContext> _options;

    private TestDatabase(string directory)
    {
        Directory = directory;
        FilePath = Path.Combine(directory, "test.db");
        _options = new DbContextOptionsBuilder<WelesDbContext>().UseSqlite($"Data Source={FilePath}").Options;
    }

    public string Directory { get; }
    public string FilePath { get; }

    public static async Task<TestDatabase> CreateAsync()
    {
        var db = new TestDatabase(TempDirectory.Create());
        await new DatabaseInitializer(db, NullLogger<DatabaseInitializer>.Instance).InitializeAsync();
        return db;
    }

    public WelesDbContext CreateDbContext() => new(_options);

    public ValueTask DisposeAsync()
    {
        SqliteConnection.ClearAllPools();
        TempDirectory.Delete(Directory);
        return ValueTask.CompletedTask;
    }
}

public static class TempDirectory
{
    public static string Create()
    {
        var path = Path.Combine(Path.GetTempPath(), "weles-tests", Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(path);
        return path;
    }

    public static void Delete(string path)
    {
        try
        {
            System.IO.Directory.Delete(path, recursive: true);
        }
        catch (IOException)
        {
            // Best effort – temp directory.
        }
    }
}
