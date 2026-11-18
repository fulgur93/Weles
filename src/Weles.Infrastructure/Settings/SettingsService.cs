using Microsoft.EntityFrameworkCore;
using Weles.Core.Entities;
using Weles.Infrastructure.Database;

namespace Weles.Infrastructure.Settings;

/// <summary>Key/value application settings persisted in SQLite.</summary>
public sealed class SettingsService(IDbContextFactory<WelesDbContext> contextFactory, TimeProvider timeProvider)
{
    public static class Keys
    {
        public const string Theme = "ui.theme";
        public const string VulnerabilityDatabaseUpdatedAt = "vulndb.updatedAt";
    }

    public async Task<string?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(cancellationToken);
        return await db.Settings.AsNoTracking().Where(s => s.Key == key).Select(s => s.Value).SingleOrDefaultAsync(cancellationToken);
    }

    public async Task SetAsync(string key, string? value, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        await using var db = await contextFactory.CreateDbContextAsync(cancellationToken);
        var setting = await db.Settings.SingleOrDefaultAsync(s => s.Key == key, cancellationToken);
        if (setting is null)
        {
            setting = new ApplicationSetting { Key = key };
            db.Settings.Add(setting);
        }

        setting.Value = value;
        setting.UpdatedAt = timeProvider.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);
    }
}
