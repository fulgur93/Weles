using System.Text.Json;

namespace Weles.Core.Import;

/// <param name="Includes">Entries to scan (IP, CIDR, range, domain) – validated later exactly like a manual entry.</param>
public sealed record TargetImportResult(IReadOnlyList<string> Includes, IReadOnlyList<string> Excludes, IReadOnlyList<string> Errors);

/// <summary>
/// Scan targets from a file – the same entries a user types into the scope form, so they go through the same validation
/// and approval. Accepted:
/// <list type="bullet">
/// <item>CSV / text: one entry per line; optional header; optional second column "exclude" (true/1/yes/tak/exclude);
/// lines starting with # are comments.</item>
/// <item>JSON: ["10.0.0.0/24", …], or [{"target": "10.0.0.1", "exclude": false}, …] (also "value", "ip", "cidr", "domain",
/// "host"), or {"targets": […], "exclude": […]}.</item>
/// </list>
/// </summary>
public static class TargetImport
{
    public const int MaxEntries = 100_000;
    private static readonly string[] ValueKeys = ["target", "value", "ip", "cidr", "domain", "host", "address", "range"];

    public static TargetImportResult Parse(string content, string fileName)
    {
        var text = content.TrimStart('﻿').Trim();
        var isJson = fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || text.StartsWith('[') || text.StartsWith('{');
        return isJson ? ParseJson(text) : ParseCsv(text);
    }

    private static TargetImportResult ParseCsv(string text)
    {
        var includes = new List<string>();
        var excludes = new List<string>();
        var errors = new List<string>();
        var lineNo = 0;
        foreach (var raw in text.Split('\n'))
        {
            lineNo++;
            var line = raw.Trim().TrimEnd('\r');
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var cells = line.Split([',', ';', '\t']).Select(c => c.Trim().Trim('"')).ToArray();
            var value = cells[0];
            if (lineNo == 1 && ValueKeys.Contains(value.ToLowerInvariant())) continue; // header
            if (value.Length == 0) continue;
            if (value.Length > 300) { errors.Add($"Wiersz {lineNo}: wpis jest za długi."); continue; }
            var exclude = cells.Length > 1 && IsTrue(cells[1]);
            (exclude ? excludes : includes).Add(value);
            if (includes.Count + excludes.Count > MaxEntries) return new([], [], [$"Plik zawiera więcej niż {MaxEntries} wpisów."]);
        }

        return new(includes.Distinct().ToList(), excludes.Distinct().ToList(), errors);
    }

    private static TargetImportResult ParseJson(string text)
    {
        var includes = new List<string>();
        var excludes = new List<string>();
        var errors = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 8, AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Object)
            {
                Collect(root.TryGetProperty("targets", out var t) ? t : root.TryGetProperty("include", out var i) ? i : default, includes, excludes, errors, false);
                Collect(root.TryGetProperty("exclude", out var e) ? e : root.TryGetProperty("excludes", out var e2) ? e2 : default, includes, excludes, errors, true);
            }
            else
            {
                Collect(root, includes, excludes, errors, false);
            }
        }
        catch (JsonException ex)
        {
            return new([], [], [$"Nieprawidłowy JSON: {ex.Message}"]);
        }

        return includes.Count + excludes.Count > MaxEntries
            ? new([], [], [$"Plik zawiera więcej niż {MaxEntries} wpisów."])
            : new(includes.Distinct().ToList(), excludes.Distinct().ToList(), errors);
    }

    private static void Collect(JsonElement element, List<string> includes, List<string> excludes, List<string> errors, bool exclude)
    {
        if (element.ValueKind != JsonValueKind.Array) return;
        var index = 0;
        foreach (var item in element.EnumerateArray())
        {
            index++;
            if (includes.Count + excludes.Count > MaxEntries) return;
            string? value = null;
            var isExclude = exclude;
            if (item.ValueKind == JsonValueKind.String) value = item.GetString();
            else if (item.ValueKind == JsonValueKind.Object)
            {
                foreach (var key in ValueKeys)
                {
                    if (item.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String) { value = v.GetString(); break; }
                }

                if (item.TryGetProperty("exclude", out var ex)) isExclude = ex.ValueKind == JsonValueKind.True || (ex.ValueKind == JsonValueKind.String && IsTrue(ex.GetString()!));
            }

            if (string.IsNullOrWhiteSpace(value) || value.Length > 300) { errors.Add($"Pozycja {index}: brak adresu (pole target/value/ip/cidr/domain)."); continue; }
            (isExclude ? excludes : includes).Add(value.Trim());
        }
    }

    private static bool IsTrue(string value) => value.Trim().ToLowerInvariant() is "true" or "1" or "yes" or "tak" or "exclude" or "wyklucz" or "x";
}
