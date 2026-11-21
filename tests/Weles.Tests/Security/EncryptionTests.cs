using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Platform;
using Weles.Tests.Support;

namespace Weles.Tests.Security;

public class EncryptionTests
{
    [Fact]
    public async Task An_existing_database_is_encrypted_and_opens_only_with_its_key()
    {
        await using var db = await TestDatabase.CreateAsync();
        const string marker = "SEKRETNY-BANER-OpenSSH_9.9-xyz";
        await using (var ctx = db.CreateDbContext())
        {
            var scan = TestData.CompletedScan(TestData.ApprovedTarget(marker), TestData.Now);
            ctx.Scans.Add(scan);
            await ctx.SaveChangesAsync();
        }

        SqliteConnection.ClearAllPools();
        Assert.True(DatabaseEncryption.IsPlaintext(db.FilePath));
        Assert.Contains(marker, Encoding.Latin1.GetString(await File.ReadAllBytesAsync(db.FilePath)));

        var paths = WelesPaths.Resolve(db.Directory);
        paths.EnsureCreated();
        var key = DatabaseEncryption.LoadOrCreateKey(paths);
        Assert.Equal(key, DatabaseEncryption.LoadOrCreateKey(paths));          // created once, then reused
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(paths.KeysDirectory, DatabaseEncryption.KeyFileName)));

        Assert.True(DatabaseEncryption.EncryptExisting(db.FilePath, key));
        Assert.False(DatabaseEncryption.EncryptExisting(db.FilePath, key));      // already encrypted – nothing to do
        Assert.False(DatabaseEncryption.IsPlaintext(db.FilePath));
        Assert.DoesNotContain(marker, Encoding.Latin1.GetString(await File.ReadAllBytesAsync(db.FilePath)));

        await using (var ctx = new WelesDbContext(new DbContextOptionsBuilder<WelesDbContext>().UseSqlite(DatabaseEncryption.ConnectionString(db.FilePath, key, pooling: false)).Options))
        {
            Assert.Equal(marker, (await ctx.ScanTargets.SingleAsync()).Name);
        }

        foreach (var wrong in new[] { null, "wrong-key" })
        {
            using var connection = new SqliteConnection(DatabaseEncryption.ConnectionString(db.FilePath, wrong, pooling: false));
            Assert.Throws<SqliteException>(() =>
            {
                connection.Open();
                using var cmd = connection.CreateCommand();
                cmd.CommandText = "SELECT count(*) FROM ScanTargets";
                cmd.ExecuteScalar();
            });
        }
    }
}
