using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Weles.Infrastructure.Platform;

namespace Weles.Infrastructure.Database;

/// <summary>
/// Encryption at rest: the whole SQLite database is encrypted with SQLCipher (AES-256, page-level, HMAC), so every field –
/// scan results, banners, audit documents, AI conversations, user accounts, integration settings – is unreadable without
/// the key. The key is 256 random bits created once in the keys directory: protected with DPAPI (machine + user) on
/// Windows, a 0600 file in the 0700 data directory on Linux; it is used as a raw key (no passphrase derivation). A database created by an earlier version (plain SQLite) is
/// converted once at startup with <c>sqlcipher_export</c> and the plain file is removed.
/// </summary>
public static class DatabaseEncryption
{
    public const string KeyFileName = "database.key";
    private static readonly byte[] PlainHeader = "SQLite format 3\0"u8.ToArray();

    /// <summary>The database password for the connection string (creates the key on first use).</summary>
    public static string LoadOrCreateKey(WelesPaths paths)
    {
        var file = Path.Combine(paths.KeysDirectory, KeyFileName);
        Directory.CreateDirectory(paths.KeysDirectory);
        if (!File.Exists(file))
        {
            var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var stored = OperatingSystem.IsWindows()
                ? "dpapi:" + Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(key), null, DataProtectionScope.CurrentUser))
                : "plain:" + key;
            using (var stream = OperatingSystem.IsWindows()
                       ? new FileStream(file, FileMode.CreateNew, FileAccess.Write)
                       : new FileStream(file, new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite }))
            using (var writer = new StreamWriter(stream))
            {
                writer.Write(stored);
            }
        }

        var text = File.ReadAllText(file).Trim();
        var secret = text switch
        {
            _ when text.StartsWith("dpapi:", StringComparison.Ordinal) && OperatingSystem.IsWindows() =>
                Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(text[6..]), null, DataProtectionScope.CurrentUser)),
            _ when text.StartsWith("plain:", StringComparison.Ordinal) => text[6..],
            _ => throw new InvalidOperationException($"Nieprawidłowy plik klucza bazy {file}.")
        };
        // A raw 256-bit key (x'…'): SQLCipher uses it directly. The key is random already, so the passphrase KDF
        // (PBKDF2, 256 000 rounds on every new connection) would only slow WELES down without adding security.
        return "x'" + Convert.ToHexString(Convert.FromBase64String(secret)) + "'";
    }

    public static bool IsPlaintext(string databaseFile)
    {
        if (!File.Exists(databaseFile) || new FileInfo(databaseFile).Length < PlainHeader.Length) return false;
        var header = new byte[PlainHeader.Length];
        using var stream = File.OpenRead(databaseFile);
        stream.ReadExactly(header);
        return header.SequenceEqual(PlainHeader);
    }

    /// <summary>Converts an existing plain database to an encrypted one (no-op when there is none or it is encrypted already).</summary>
    /// <returns>True when a conversion happened.</returns>
    public static bool EncryptExisting(string databaseFile, string key)
    {
        if (!IsPlaintext(databaseFile)) return false;
        var encrypted = databaseFile + ".encrypting";
        File.Delete(encrypted);
        using (var plain = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databaseFile, Pooling = false }.ToString()))
        {
            plain.Open();
            Execute(plain, "PRAGMA wal_checkpoint(TRUNCATE);");
            Execute(plain, $"ATTACH DATABASE {Quote(encrypted)} AS encrypted KEY {Quote(key)};");
            Execute(plain, "SELECT sqlcipher_export('encrypted');");
            Execute(plain, "DETACH DATABASE encrypted;");
        }

        SqliteConnection.ClearAllPools();
        // The encrypted copy must open with the key before the plain file goes.
        using (var check = new SqliteConnection(ConnectionString(encrypted, key, pooling: false)))
        {
            check.Open();
            Execute(check, "SELECT count(*) FROM sqlite_master;");
        }

        File.Move(encrypted, databaseFile, overwrite: true);
        foreach (var suffix in (string[])["-wal", "-shm"]) File.Delete(databaseFile + suffix);
        return true;
    }

    public static string ConnectionString(string databaseFile, string? key, bool pooling = true) => new SqliteConnectionStringBuilder
    {
        DataSource = databaseFile,
        DefaultTimeout = 30,
        Pooling = pooling,
        Password = key
    }.ToString();

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static string Quote(string value) => "'" + value.Replace("'", "''") + "'";
}
