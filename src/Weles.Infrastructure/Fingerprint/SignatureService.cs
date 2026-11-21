using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Weles.Core.Entities;
using Weles.Core.Fingerprint;
using Weles.Infrastructure.Database;

namespace Weles.Infrastructure.Fingerprint;

public sealed record CustomSignatureView(int Id, Signature? Signature, string Json, bool Enabled, DateTime UpdatedAt, string? UpdatedBy, IReadOnlyList<string> Errors);

/// <summary>A web service where a signature matched (signature test and technology lists).</summary>
public sealed record SignatureHit(int ServiceId, int ScanId, int? AssetId, string Ip, int Port, string Url, string? Title, TechnologyMatch Match);

public sealed record SignatureSaveResult(bool Success, IReadOnlyList<string> Errors, string? SignatureId = null);

/// <summary>
/// Detection signatures: the built-in set (code) plus the user's own (database, JSON). Signatures are evaluated on the
/// stored web observations after every scan – and again for all stored observations when a signature changes, so a new
/// signature works on past scans without scanning again.
/// </summary>
public sealed class SignatureService(IDbContextFactory<WelesDbContext> contextFactory, TimeProvider time, ILogger<SignatureService> logger)
{
    public const int MaxImport = 500;

    public IReadOnlyList<Signature> BuiltIn => SignatureEngine.BuiltIn;

    public async Task<IReadOnlyList<CustomSignatureView>> CustomAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var rows = await db.CustomSignatures.AsNoTracking().OrderBy(s => s.SignatureId).ToListAsync(ct);
        return rows.Select(r =>
        {
            var parsed = Parse(r.Json, out var error);
            return new CustomSignatureView(r.Id, parsed, r.Json, r.Enabled, r.UpdatedAt, r.UpdatedBy, error is null ? SignatureEngine.Validate(parsed) : [error]);
        }).ToList();
    }

    /// <summary>Built-in signatures and the user's enabled, valid ones.</summary>
    public async Task<IReadOnlyList<Signature>> ActiveAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        return [.. SignatureEngine.BuiltIn, .. await EnabledCustomAsync(db, ct)];
    }

    /// <summary>Paths the user's signatures need requested during scans.</summary>
    internal static async Task<IReadOnlyList<string>> CustomPathsAsync(WelesDbContext db, CancellationToken ct) =>
        SignatureEngine.PathsOf(await EnabledCustomAsync(db, ct));

    /// <summary>Adds or replaces a custom signature (by its id). Built-in ids cannot be overridden.</summary>
    public async Task<SignatureSaveResult> SaveAsync(string json, string? user, CancellationToken ct = default)
    {
        var signature = Parse(json, out var parseError);
        if (parseError is not null) return new SignatureSaveResult(false, [parseError]);
        var errors = SignatureEngine.Validate(signature).ToList();
        if (signature is not null && SignatureEngine.BuiltIn.Any(b => b.Id == signature.Id)) errors.Add($"Identyfikator „{signature.Id}” należy do sygnatury wbudowanej – wybierz inny.");
        if (errors.Count > 0) return new SignatureSaveResult(false, errors);

        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var now = time.GetUtcNow().UtcDateTime;
        var row = await db.CustomSignatures.SingleOrDefaultAsync(s => s.SignatureId == signature!.Id, ct);
        if (row is null)
        {
            row = new CustomSignature { SignatureId = signature!.Id, Json = "", CreatedAt = now };
            db.CustomSignatures.Add(row);
        }

        row.Json = JsonSerializer.Serialize(signature, SignatureEngine.Json);
        row.UpdatedAt = now;
        row.UpdatedBy = user;
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Custom signature {Id} saved by {User}", signature!.Id, user ?? "-");
        await ReevaluateAsync(ct);
        return new SignatureSaveResult(true, [], signature.Id);
    }

    /// <summary>Imports one signature or a JSON array of them; every invalid one is reported, the valid ones are stored.</summary>
    public async Task<(int Saved, IReadOnlyList<string> Errors)> ImportAsync(string json, string? user, CancellationToken ct = default)
    {
        List<JsonElement> items;
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            items = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().Select(e => e.Clone()).ToList() : [doc.RootElement.Clone()];
        }
        catch (JsonException ex)
        {
            return (0, [$"Nieprawidłowy JSON: {ex.Message}"]);
        }

        if (items.Count > MaxImport) return (0, [$"Najwyżej {MaxImport} sygnatur w jednym pliku."]);
        var saved = 0;
        var errors = new List<string>();
        foreach (var item in items)
        {
            var result = await SaveAsync(item.GetRawText(), user, ct);
            if (result.Success) saved++;
            else errors.Add($"{(item.ValueKind == JsonValueKind.Object && item.TryGetProperty("id", out var id) ? id.ToString() : "?")}: {string.Join(" ", result.Errors)}");
        }

        return (saved, errors);
    }

    public async Task<string> ExportAsync(CancellationToken ct = default)
    {
        var custom = await CustomAsync(ct);
        return JsonSerializer.Serialize(custom.Where(c => c.Signature is not null).Select(c => c.Signature), SignatureEngine.Json);
    }

    public async Task SetEnabledAsync(int id, bool enabled, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        await db.CustomSignatures.Where(s => s.Id == id).ExecuteUpdateAsync(u => u.SetProperty(s => s.Enabled, enabled), ct);
        await ReevaluateAsync(ct);
    }

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        await db.CustomSignatures.Where(s => s.Id == id).ExecuteDeleteAsync(ct);
        await ReevaluateAsync(ct);
    }

    /// <summary>Where a signature (not saved yet) would match among the latest observations of every web service.</summary>
    public async Task<IReadOnlyList<SignatureHit>> TestAsync(Signature signature, int take = 50, CancellationToken ct = default)
    {
        var hits = new List<SignatureHit>();
        foreach (var o in await LatestObservationsAsync(ct))
        {
            if (SignatureEngine.Evaluate(o.Web, [signature]).FirstOrDefault() is { } match)
            {
                hits.Add(new SignatureHit(o.ServiceId, o.ScanId, o.AssetId, o.Ip, o.Port, o.Web.Url, o.Web.Title, match));
                if (hits.Count >= take) break;
            }
        }

        return hits;
    }

    /// <summary>Evaluates every signature on the web services of one scan (after the scan).</summary>
    public async Task<int> EvaluateScanAsync(int scanId, CancellationToken ct = default) =>
        await EvaluateAsync(db => db.DiscoveredServices.Where(s => s.WebJson != null && s.Port!.Host!.ScanId == scanId), ct);

    /// <summary>Evaluates every stored observation again – after the user changed the signatures.</summary>
    public async Task<int> ReevaluateAsync(CancellationToken ct = default) =>
        await EvaluateAsync(db => db.DiscoveredServices.Where(s => s.WebJson != null), ct);

    private async Task<int> EvaluateAsync(Func<WelesDbContext, IQueryable<DiscoveredService>> services, CancellationToken ct)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        IReadOnlyList<Signature> signatures = [.. SignatureEngine.BuiltIn, .. await EnabledCustomAsync(db, ct)];
        var rows = await services(db).AsNoTracking().Select(s => new { s.Id, s.WebJson }).ToListAsync(ct);
        var found = 0;
        foreach (var chunk in rows.Chunk(200))
        {
            var ids = chunk.Select(r => r.Id).ToList();
            await db.ServiceTechnologies.Where(t => ids.Contains(t.DiscoveredServiceId)).ExecuteDeleteAsync(ct);
            foreach (var row in chunk)
            {
                if (Observation(row.WebJson) is not { } web) continue;
                foreach (var m in SignatureEngine.Evaluate(web, signatures))
                {
                    db.ServiceTechnologies.Add(new ServiceTechnology
                    {
                        DiscoveredServiceId = row.Id, SignatureId = m.SignatureId, Name = m.Name, Category = m.Category, Version = m.Version, Confidence = m.Confidence, Cwe = m.Cwe,
                        Evidence = Cut(string.Join('\n', m.Evidence), 4000)
                    });
                    found++;
                }
            }

            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }

        return found;
    }

    private sealed record LatestObservation(int ServiceId, int ScanId, int? AssetId, string Ip, int Port, WebObservation Web);

    private async Task<List<LatestObservation>> LatestObservationsAsync(CancellationToken ct)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var rows = await db.DiscoveredServices.AsNoTracking().Where(s => s.WebJson != null)
            .Select(s => new { s.Id, s.WebJson, s.Port!.Port, s.Port.Host!.ScanId, s.Port.Host.AssetId, s.Port.Host.IpAddress })
            .ToListAsync(ct);
        return rows.GroupBy(r => (r.AssetId ?? -r.Id, r.Port)).Select(g => g.MaxBy(r => r.ScanId)!)
            .Select(r => Observation(r.WebJson) is { } web ? new LatestObservation(r.Id, r.ScanId, r.AssetId, r.IpAddress, r.Port, web) : null)
            .OfType<LatestObservation>().ToList();
    }

    public static WebObservation? Observation(string? json)
    {
        if (json is null) return null;
        try
        {
            return JsonSerializer.Deserialize<WebObservation>(json, SignatureEngine.Json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static async Task<List<Signature>> EnabledCustomAsync(WelesDbContext db, CancellationToken ct) =>
        (await db.CustomSignatures.AsNoTracking().Where(s => s.Enabled).Select(s => s.Json).ToListAsync(ct))
        .Select(j => Parse(j, out _)).Where(s => s is not null && SignatureEngine.Validate(s).Count == 0).Cast<Signature>().ToList();

    public static Signature? Parse(string json, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(json) || json.Length > 20_000)
        {
            error = "Sygnatura musi być niepustym JSON-em do 20 000 znaków.";
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<Signature>(json, SignatureEngine.Json);
        }
        catch (JsonException ex)
        {
            error = $"Nieprawidłowy JSON sygnatury: {ex.Message}";
            return null;
        }
    }

    private static string? Cut(string? value, int max) => value is null || value.Length <= max ? value : value[..max];
}
