using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Weles.App.Localization;

/// <summary>
/// UI dictionary. Polish is the source language: every text in the code is written in Polish and is its own key, so a
/// missing translation degrades to Polish instead of a raw key. English comes from the embedded <c>en.json</c>.
/// The language follows <see cref="CultureInfo.CurrentUICulture"/>, which Blazor takes from the request that opens the
/// circuit (see <see cref="LanguageState"/>).
/// </summary>
public static class L
{
    private static readonly Lazy<Dictionary<string, string>> English = new(() => Load("Weles.App.Localization.en.json"));
    private static readonly Lazy<IReadOnlyList<(Regex Pattern, string Key)>> Templates = new(BuildTemplates);
    private static readonly ConcurrentDictionary<string, string> MessageCache = new();

    public static bool IsEnglish => CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "en";

    /// <summary>Translates a fixed UI text.</summary>
    public static string T(string polish) => IsEnglish && English.Value.TryGetValue(polish, out var en) ? en : polish;

    /// <summary>Translates a text with placeholders ("Ukryto {0} urządzeń") and formats it in the current culture.</summary>
    public static string F(string polish, params object?[] args) => string.Format(CultureInfo.CurrentCulture, T(polish), args);

    /// <summary>
    /// Translates text WELES generated and stored earlier in Polish (scan events, classification reasons, match
    /// reasons, validation errors). Exact entries first, then templates with {0}…{n} – captured values are translated
    /// recursively; composite texts are split at "\n", " | ", "; ", " – " and ", ". Unknown parts stay as they are (e.g. NVD data).
    /// </summary>
    public static string Message(string? stored)
    {
        if (string.IsNullOrEmpty(stored) || !IsEnglish) return stored ?? "";
        return MessageCache.GetOrAdd(stored, static s => TranslateComposite(s, 0));
    }

    /// <summary>All dictionary keys – used by the completeness tests.</summary>
    public static IReadOnlyDictionary<string, string> Dictionary => English.Value;

    private static string TranslateComposite(string text, int depth)
    {
        // Lines and " | " lists are never part of one template – split them before matching templates.
        foreach (var separator in (string[])["\n", " | "])
        {
            if (text.Contains(separator)) return string.Join(separator, text.Split(separator).Select(p => TranslateComposite(p, depth)));
        }

        if (TryTranslate(text, depth, out var whole)) return whole;
        foreach (var separator in (string[])["; ", " – ", ", "])
        {
            if (!text.Contains(separator)) continue;
            var parts = text.Split(separator);
            return string.Join(separator, parts.Select(p => TranslateComposite(p, depth)));
        }

        return text;
    }

    private static bool TryTranslate(string text, int depth, out string result)
    {
        var dict = English.Value;
        var trimmed = text.Trim();
        if (trimmed.Length == 0)
        {
            result = text;
            return true;
        }

        if (dict.TryGetValue(trimmed, out var exact))
        {
            result = text.Replace(trimmed, exact);
            return true;
        }

        // Sentence punctuation is often added by the composer ("…adresów." vs "…adresów").
        if (trimmed[^1] is '.' && dict.TryGetValue(trimmed[..^1], out var noDot))
        {
            result = text.Replace(trimmed, noDot + ".");
            return true;
        }

        if (depth < 4)
        {
            foreach (var (pattern, key) in Templates.Value)
            {
                var m = pattern.Match(trimmed);
                if (!m.Success) continue;
                var args = m.Groups.Cast<Group>().Skip(1).Select(g => (object)TranslateComposite(g.Value, depth + 1)).ToArray();
                result = text.Replace(trimmed, string.Format(CultureInfo.InvariantCulture, dict[key], args));
                return true;
            }
        }

        result = text;
        return false;
    }

    private static List<(Regex, string)> BuildTemplates()
    {
        var list = new List<(Regex, string, int)>();
        foreach (var key in English.Value.Keys.Where(k => k.Contains("{0")))
        {
            // "{0} {1}" or "{0}: {1}" would match any text – only templates with real words can identify a message.
            if (PlaceholderRx().Replace(key, "").Count(char.IsLetter) < 3) continue;
            var pattern = "^" + PlaceholderRx().Replace(Regex.Escape(key).Replace(@"\{", "{"), "(.+?)") + "$";
            // Literal length: more specific templates win ("Skan zakończony: …" before "{0}: {1}").
            var literal = PlaceholderRx().Replace(key, "").Length;
            list.Add((new Regex(pattern, RegexOptions.CultureInvariant), key, literal));
        }

        return list.OrderByDescending(t => t.Item3).Select(t => (t.Item1, t.Item2)).ToList();
    }

    private static Dictionary<string, string> Load(string resource)
    {
        using var stream = typeof(L).Assembly.GetManifestResourceStream(resource) ?? throw new InvalidOperationException($"Missing {resource}");
        var entries = JsonSerializer.Deserialize<Dictionary<string, string>>(stream) ?? [];
        return new Dictionary<string, string>(entries, StringComparer.Ordinal);
    }

    private static Regex PlaceholderRx() => Placeholder;
    private static readonly Regex Placeholder = new(@"\{\d+(?::[^}]*)?\}", RegexOptions.Compiled);
}
