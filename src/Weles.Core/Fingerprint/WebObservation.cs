namespace Weles.Core.Fingerprint;

/// <summary>A cookie as the server set it – name and security flags only; the value is never stored.</summary>
public sealed record WebCookie(string Name, bool Secure, bool HttpOnly, string? SameSite);

/// <summary>A safe GET of a well-known path (e.g. /admin, /version) – no parameters, no credentials, no login attempts.</summary>
public sealed record WebPathResult(string Path, int Status, string? Title, int Length, string? BodySample, string? Location = null);

/// <summary>
/// What an HTTP(S) service showed to a plain browser-like GET: final status and title, all response headers, cookies
/// (names and flags), the redirect chain, a bounded part of the page, the favicon hash and the results of a few safe
/// path requests. Signatures are evaluated on this record – also later, when the user adds a new signature.
/// </summary>
/// <param name="Redirects">"302 → /login" – every hop of the same-origin redirect chain.</param>
/// <param name="FaviconMmh3">MurmurHash3 of the base64 favicon (the value Shodan and many fingerprint lists use).</param>
public sealed record WebObservation(
    string Url,
    int Status,
    string? Title,
    IReadOnlyDictionary<string, string> Headers,
    IReadOnlyList<WebCookie> Cookies,
    IReadOnlyList<string> Redirects,
    string Body,
    int? FaviconMmh3,
    string? FaviconMd5,
    IReadOnlyList<WebPathResult> Paths)
{
    public const int MaxBodyChars = 16 * 1024;
    public const int MaxPathSampleChars = 2048;
    public const int MaxHeaders = 60;
    public const int MaxHeaderValueChars = 1024;
    public const int MaxCookies = 40;
    public const int MaxPaths = 16;

    public string? Header(string name) => Headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;

    /// <summary>Bounded copy – used for data from the network and from agents before it is stored.</summary>
    public WebObservation Bounded() => this with
    {
        Url = Cut(Url, 512)!,
        Title = Cut(Title, 300),
        Headers = Headers.Take(MaxHeaders).ToDictionary(h => Cut(h.Key, 100)!, h => Cut(h.Value, MaxHeaderValueChars)!, StringComparer.OrdinalIgnoreCase),
        Cookies = Cookies.Take(MaxCookies).Select(c => c with { Name = Cut(c.Name, 100)!, SameSite = Cut(c.SameSite, 20) }).ToList(),
        Redirects = Redirects.Take(5).Select(r => Cut(r, 300)!).ToList(),
        Body = Cut(Body, MaxBodyChars) ?? "",
        FaviconMd5 = Cut(FaviconMd5, 32),
        Paths = Paths.Take(MaxPaths).Select(p => p with { Path = Cut(p.Path, 200)!, Title = Cut(p.Title, 300), BodySample = Cut(p.BodySample, MaxPathSampleChars), Location = Cut(p.Location, 300) }).ToList()
    };

    private static string? Cut(string? value, int max) => value is null || value.Length <= max ? value : value[..max];
}

/// <summary>Cookies from Set-Cookie headers: name and flags; the value is dropped at once.</summary>
public static class WebCookies
{
    public static IReadOnlyList<WebCookie> Parse(IEnumerable<string> setCookies)
    {
        var result = new List<WebCookie>();
        foreach (var header in setCookies)
        {
            var parts = header.Split(';', StringSplitOptions.TrimEntries);
            var eq = parts[0].IndexOf('=');
            var name = (eq < 0 ? parts[0] : parts[0][..eq]).Trim();
            if (name.Length == 0 || result.Any(c => c.Name == name)) continue;
            bool Has(string flag) => parts.Skip(1).Any(p => p.Equals(flag, StringComparison.OrdinalIgnoreCase));
            var sameSite = parts.Skip(1).FirstOrDefault(p => p.StartsWith("SameSite=", StringComparison.OrdinalIgnoreCase))?[9..];
            result.Add(new WebCookie(name, Has("Secure"), Has("HttpOnly"), sameSite));
        }

        return result;
    }
}

/// <summary>Favicon hashes: MurmurHash3 (x86, 32-bit, seed 0) of the base64 text with a line break every 76 characters.</summary>
public static class FaviconHash
{
    public static int Mmh3(byte[] icon)
    {
        var base64 = Convert.ToBase64String(icon);
        var sb = new System.Text.StringBuilder(base64.Length + base64.Length / 76 + 1);
        for (var i = 0; i < base64.Length; i += 76)
        {
            sb.Append(base64, i, Math.Min(76, base64.Length - i)).Append('\n');
        }

        return Murmur3(System.Text.Encoding.ASCII.GetBytes(sb.ToString()));
    }

    public static string Md5(byte[] icon) => Convert.ToHexStringLower(System.Security.Cryptography.MD5.HashData(icon));

    public static int Murmur3(byte[] data, uint seed = 0)
    {
        const uint c1 = 0xcc9e2d51, c2 = 0x1b873593;
        var h = seed;
        var blocks = data.Length / 4;
        for (var i = 0; i < blocks; i++)
        {
            var k = BitConverter.ToUInt32(data, i * 4);
            k *= c1; k = (k << 15) | (k >> 17); k *= c2;
            h ^= k; h = (h << 13) | (h >> 19); h = h * 5 + 0xe6546b64;
        }

        uint tail = 0;
        var rest = data.Length & 3;
        var offset = blocks * 4;
        if (rest == 3) tail ^= (uint)data[offset + 2] << 16;
        if (rest >= 2) tail ^= (uint)data[offset + 1] << 8;
        if (rest >= 1)
        {
            tail ^= data[offset];
            tail *= c1; tail = (tail << 15) | (tail >> 17); tail *= c2; h ^= tail;
        }

        h ^= (uint)data.Length;
        h ^= h >> 16; h *= 0x85ebca6b; h ^= h >> 13; h *= 0xc2b2ae35; h ^= h >> 16;
        return unchecked((int)h);
    }
}
