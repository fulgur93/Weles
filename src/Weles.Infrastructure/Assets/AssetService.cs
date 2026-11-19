using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Weles.Core.Enums;
using Weles.Core.Rules;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Scanning;

namespace Weles.Infrastructure.Assets;

public sealed record AssetEditInput(string? CustomName, AssetType? UserAssetType, AssetCriticality Criticality, string? Notes);

/// <summary>User-maintained asset data. These fields are never touched by scans.</summary>
public sealed class AssetService(IDbContextFactory<WelesDbContext> contextFactory, ILogger<AssetService> logger)
{
    public const int MaxNotesLength = 4000;

    public async Task<OperationResult> UpdateAsync(int assetId, AssetEditInput input, CancellationToken ct = default)
    {
        var errors = new List<string>();
        var name = string.IsNullOrWhiteSpace(input.CustomName) ? null : input.CustomName.Trim();
        var notes = string.IsNullOrWhiteSpace(input.Notes) ? null : input.Notes.Trim();
        if (name?.Length > AssetNaming.MaxNameLength) errors.Add($"Nazwa może mieć maksymalnie {AssetNaming.MaxNameLength} znaków.");
        if (notes?.Length > MaxNotesLength) errors.Add($"Notatki mogą mieć maksymalnie {MaxNotesLength} znaków.");
        if (!Enum.IsDefined(input.Criticality)) errors.Add("Nieprawidłowa krytyczność.");
        if (input.UserAssetType is { } t && !Enum.IsDefined(t)) errors.Add("Nieprawidłowy typ urządzenia.");
        if (errors.Count > 0) return new OperationResult(false, errors);

        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var asset = await db.Assets.SingleOrDefaultAsync(a => a.Id == assetId, ct);
        if (asset is null) return OperationResult.Fail("Urządzenie nie istnieje.");

        asset.CustomName = name;
        asset.UserAssetType = input.UserAssetType;
        asset.Criticality = input.Criticality;
        asset.Notes = notes;
        asset.DisplayName = AssetNaming.DisplayName(name, asset.Hostname, AssetNaming.Label(asset.Model, asset.Vendor), asset.PrimaryIpAddress);
        await db.SaveChangesAsync(ct);

        logger.LogInformation("Asset {AssetId} updated by the user (custom name: {HasName}, type override: {HasType}, criticality: {Criticality})",
            assetId, name is not null, input.UserAssetType is not null, input.Criticality);
        return OperationResult.Ok(assetId);
    }
}
