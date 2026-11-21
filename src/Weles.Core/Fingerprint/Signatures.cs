using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Weles.Core.Fingerprint;

public enum SignatureCategory
{
    Cms,
    Framework,
    Server,
    Language,
    Iot,
    AdminPanel,
    Staging,
    Interesting,
    Other
}

/// <summary>
/// One condition of a signature. Types: <c>header</c> (Name, optional Pattern on the value), <c>cookie</c> (Pattern on the
/// cookie name), <c>body</c>, <c>title</c>, <c>server</c> (Pattern), <c>status</c> (Status list), <c>favicon</c> (Hash =
/// MurmurHash3, or Pattern = MD5), <c>path</c> (Path requested with GET; optional Status list and Pattern on its body/title),
/// <c>url</c> (Pattern on the address or host name – e.g. "staging").
/// </summary>
public sealed record SignatureCondition(string Type, string? Name = null, string? Pattern = null, string? Path = null, IReadOnlyList<int>? Status = null, long? Hash = null);

/// <param name="Source">Where the version is: body, title, server, header:&lt;name&gt; or path:&lt;path&gt;.</param>
/// <param name="Pattern">Regular expression; the first group is the version.</param>
public sealed record SignatureVersion(string Source, string Pattern);

/// <summary>
/// A safe detection signature: it only looks at what a normal GET returns (headers, cookies, page, favicon, a few
/// well-known paths). It can never send credentials, form data or exploit payloads – the format has no way to express them.
/// </summary>
/// <param name="Match">"any" – one condition is enough; "all" – every condition must hold.</param>
/// <param name="Confidence">0–100 when the signature matches with one condition; each further matching condition adds 5.</param>
/// <param name="Cwe">MITRE CWE the finding maps to (e.g. 489 – active debug code), exported to DefectDojo.</param>
public sealed record Signature(
    string Id,
    string Name,
    SignatureCategory Category,
    IReadOnlyList<SignatureCondition> Conditions,
    string Match = "any",
    SignatureVersion? Version = null,
    int Confidence = 80,
    string? Description = null,
    IReadOnlyList<string>? Tags = null,
    int? Cwe = null);

/// <param name="Evidence">"header X-Powered-By: PHP/8.1", "path /wp-login.php → 200" – why it matched.</param>
public sealed record TechnologyMatch(string SignatureId, string Name, SignatureCategory Category, string? Version, int Confidence, IReadOnlyList<string> Evidence, int? Cwe = null);

public static partial class SignatureEngine
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false) },
        WriteIndented = true,
        MaxDepth = 16
    };

    /// <summary>Patterns come from users: case-insensitive, and every match is cut off after 100 ms (no catastrophic backtracking).</summary>
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    public static readonly string[] ConditionTypes = ["header", "cookie", "body", "title", "server", "status", "favicon", "path", "url"];

    public static IReadOnlyList<Signature> BuiltIn { get; } = LoadBuiltIn();

    public static IReadOnlyList<TechnologyMatch> Evaluate(WebObservation web, IEnumerable<Signature> signatures)
    {
        var result = new List<TechnologyMatch>();
        foreach (var signature in signatures)
        {
            var evidence = new List<string>();
            var matched = 0;
            foreach (var condition in signature.Conditions)
            {
                if (Check(web, condition) is { } why)
                {
                    matched++;
                    evidence.Add(why);
                }
            }

            var ok = signature.Match == "all" ? matched == signature.Conditions.Count && matched > 0 : matched > 0;
            if (!ok) continue;
            var confidence = Math.Clamp(signature.Confidence + 5 * (matched - 1), 1, 99);
            result.Add(new TechnologyMatch(signature.Id, signature.Name, signature.Category, VersionOf(web, signature.Version), confidence, evidence, signature.Cwe));
        }

        // One technology from several signatures (built-in and custom) – keep the most certain, with a version if any has one.
        return result.GroupBy(m => (m.Name.ToLowerInvariant(), m.Category))
            .Select(g => g.OrderByDescending(m => m.Confidence).First() with { Version = g.Select(m => m.Version).FirstOrDefault(v => v is not null) })
            .OrderBy(m => m.Category).ThenByDescending(m => m.Confidence).ThenBy(m => m.Name, StringComparer.Ordinal).ToList();
    }

    /// <summary>Paths the signatures want requested (bounded, safe GETs only).</summary>
    public static IReadOnlyList<string> PathsOf(IEnumerable<Signature> signatures) =>
        signatures.SelectMany(s => s.Conditions).Where(c => c.Type == "path" && c.Path is not null).Select(c => c.Path!)
            .Concat(signatures.Where(s => s.Version?.Source.StartsWith("path:", StringComparison.Ordinal) == true).Select(s => s.Version!.Source[5..]))
            .Where(IsSafePath).Distinct(StringComparer.Ordinal).ToList();

    /// <summary>Null when the signature can be used; otherwise every problem, in Polish.</summary>
    public static IReadOnlyList<string> Validate(Signature? s)
    {
        if (s is null) return ["Pusta sygnatura."];
        var errors = new List<string>();
        if (s.Id is null || !IdPattern().IsMatch(s.Id)) errors.Add("Identyfikator: 2–64 znaki: małe litery, cyfry, „-”, „_”, „.”.");
        if (string.IsNullOrWhiteSpace(s.Name) || s.Name.Length > 100) errors.Add("Nazwa: od 1 do 100 znaków.");
        if (!Enum.IsDefined(s.Category)) errors.Add("Nieznana kategoria.");
        if (s.Match is not ("any" or "all")) errors.Add("Pole match: „any” albo „all”.");
        if (s.Confidence is < 1 or > 99) errors.Add("Pewność: 1–99.");
        if (s.Description is { Length: > 500 }) errors.Add("Opis: najwyżej 500 znaków.");
        if (s.Conditions is null || s.Conditions.Count is 0 or > 20) errors.Add("Od 1 do 20 warunków.");
        foreach (var (c, i) in (s.Conditions ?? []).Select((c, i) => (c, i + 1)))
        {
            if (c is null || !ConditionTypes.Contains(c.Type)) { errors.Add($"Warunek {i}: typ musi być jednym z: {string.Join(", ", ConditionTypes)}."); continue; }
            if (c.Pattern is { } p && !IsValidPattern(p)) errors.Add($"Warunek {i}: nieprawidłowe wyrażenie regularne.");
            switch (c.Type)
            {
                case "header" when string.IsNullOrWhiteSpace(c.Name) || c.Name.Length > 100:
                    errors.Add($"Warunek {i}: podaj nazwę nagłówka (name)."); break;
                case "cookie" or "body" or "title" or "server" or "url" when string.IsNullOrEmpty(c.Pattern):
                    errors.Add($"Warunek {i}: podaj wzorzec (pattern)."); break;
                case "status" when c.Status is not { Count: > 0 }:
                    errors.Add($"Warunek {i}: podaj kody HTTP (status)."); break;
                case "favicon" when c.Hash is null && string.IsNullOrEmpty(c.Pattern):
                    errors.Add($"Warunek {i}: podaj hash favicony (hash – mmh3) albo MD5 (pattern)."); break;
                case "path" when c.Path is null || !IsSafePath(c.Path):
                    errors.Add($"Warunek {i}: ścieżka musi zaczynać się od „/”, bez „..”, parametrów i znaków specjalnych (najwyżej 100 znaków)."); break;
            }

            if (c.Status is { } codes && codes.Any(x => x is < 100 or > 599)) errors.Add($"Warunek {i}: kody HTTP 100–599.");
        }

        if (s.Version is { } v)
        {
            if (!IsValidPattern(v.Pattern)) errors.Add("Wersja: nieprawidłowe wyrażenie regularne.");
            if (v.Source is not ("body" or "title" or "server") && !v.Source.StartsWith("header:", StringComparison.Ordinal)
                && !(v.Source.StartsWith("path:", StringComparison.Ordinal) && IsSafePath(v.Source[5..])))
                errors.Add("Wersja: źródło body, title, server, header:<nazwa> albo path:<ścieżka>.");
        }

        if (s.Cwe is < 1 or > 2000) errors.Add("CWE: numer 1–2000.");
        if (s.Tags is { } tags && (tags.Count > 10 || tags.Any(t => t is null || t.Length > 40))) errors.Add("Najwyżej 10 tagów po 40 znaków.");
        return errors;
    }

    /// <summary>Only plain paths: no query string (nothing is submitted), no traversal, no control characters.</summary>
    public static bool IsSafePath(string path) => path.Length is > 0 and <= 100 && SafePath().IsMatch(path) && !path.Contains("..", StringComparison.Ordinal);

    private static bool IsValidPattern(string pattern)
    {
        if (pattern.Length > 300) return false;
        try
        {
            _ = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool IsMatch(string? input, string pattern, out string? value)
    {
        value = null;
        if (input is null) return false;
        try
        {
            var m = Regex.Match(input, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
            if (!m.Success) return false;
            value = m.Groups.Count > 1 && m.Groups[1].Success ? m.Groups[1].Value : m.Value;
            return true;
        }
        catch (Exception ex) when (ex is RegexMatchTimeoutException or ArgumentException)
        {
            return false;
        }
    }

    private static string? Check(WebObservation web, SignatureCondition c)
    {
        switch (c.Type)
        {
            case "header":
                var value = web.Header(c.Name ?? "");
                if (value is null) return null;
                if (c.Pattern is null) return $"nagłówek {c.Name}: {Short(value)}";
                return IsMatch(value, c.Pattern, out _) ? $"nagłówek {c.Name}: {Short(value)}" : null;
            case "cookie":
                var cookie = web.Cookies.FirstOrDefault(k => IsMatch(k.Name, c.Pattern!, out _));
                return cookie is null ? null : $"ciasteczko {cookie.Name}";
            case "body":
                return IsMatch(web.Body, c.Pattern!, out var b) ? $"treść strony: {Short(b)}" : null;
            case "title":
                return IsMatch(web.Title, c.Pattern!, out _) ? $"tytuł: {Short(web.Title)}" : null;
            case "server":
                return IsMatch(web.Header("Server"), c.Pattern!, out _) ? $"Server: {Short(web.Header("Server"))}" : null;
            case "status":
                return c.Status?.Contains(web.Status) == true ? $"kod HTTP {web.Status}" : null;
            case "url":
                return IsMatch(web.Url, c.Pattern!, out _) ? $"adres: {Short(web.Url)}" : null;
            case "favicon":
                if (c.Hash is { } hash && web.FaviconMmh3 == hash) return $"favicon mmh3 {hash}";
                return c.Pattern is { } md5 && web.FaviconMd5 is { } actual && actual.Equals(md5, StringComparison.OrdinalIgnoreCase) ? $"favicon md5 {actual}" : null;
            case "path":
                var path = web.Paths.FirstOrDefault(p => p.Path == c.Path);
                if (path is null || path.Status == 0) return null;
                if (c.Status is { Count: > 0 } statuses ? !statuses.Contains(path.Status) : path.Status is not (>= 200 and < 300)) return null;
                if (c.Pattern is not null && !IsMatch($"{path.Title}\n{path.BodySample}", c.Pattern, out _)) return null;
                return $"ścieżka {path.Path} → {path.Status}" + (path.Title is null ? "" : $" ({Short(path.Title)})");
            default:
                return null;
        }
    }

    private static string? VersionOf(WebObservation web, SignatureVersion? version)
    {
        if (version is null) return null;
        var input = version.Source switch
        {
            "body" => web.Body,
            "title" => web.Title,
            "server" => web.Header("Server"),
            var s when s.StartsWith("header:", StringComparison.Ordinal) => web.Header(s[7..]),
            var s when s.StartsWith("path:", StringComparison.Ordinal) => web.Paths.FirstOrDefault(p => p.Path == s[5..]) is { } p ? $"{p.Title}\n{p.BodySample}" : null,
            _ => null
        };
        return IsMatch(input, version.Pattern, out var v) && v is { Length: > 0 and <= 40 } && VersionLike().IsMatch(v) ? v : null;
    }

    private static string Short(string? value) => value is null ? "" : value.Length > 80 ? value[..80] + "…" : value;

    private static IReadOnlyList<Signature> LoadBuiltIn()
    {
        using var stream = typeof(SignatureEngine).Assembly.GetManifestResourceStream("Weles.Core.signatures.json")
                           ?? throw new InvalidOperationException("Embedded signatures missing.");
        var list = JsonSerializer.Deserialize<List<Signature>>(stream, Json) ?? [];
        var invalid = list.Select(s => (s.Id, Errors: Validate(s))).Where(x => x.Errors.Count > 0).ToList();
        if (invalid.Count > 0) throw new InvalidOperationException("Invalid built-in signature: " + string.Join("; ", invalid.Select(x => $"{x.Id}: {string.Join(" ", x.Errors)}")));
        return list;
    }

    [GeneratedRegex(@"^[a-z0-9][a-z0-9._-]{1,63}$")]
    private static partial Regex IdPattern();

    [GeneratedRegex(@"^/[A-Za-z0-9._~/\-]*$")]
    private static partial Regex SafePath();

    [GeneratedRegex(@"^[0-9][0-9A-Za-z.\-_+]*$")]
    private static partial Regex VersionLike();
}
