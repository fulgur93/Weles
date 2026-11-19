using System.Text.RegularExpressions;

namespace Weles.Core.Vulnerabilities;

/// <summary>
/// Compares software versions the way vendors and NVD write them: "2.4.52", "8.9p1", "1.0.2k", "9.18.0-rc1", "5.7.44-log".
/// Numbers compare numerically, trailing zero components are insignificant ("1.0" = "1.0.0"), pre-release markers
/// (alpha, beta, rc, pre, dev) sort before the release and other suffixes (p1, OpenSSL letters "a"…"z") after it.
/// </summary>
public static partial class VersionComparer
{
    private static readonly HashSet<string> PreRelease = new(StringComparer.OrdinalIgnoreCase) { "alpha", "beta", "rc", "pre", "preview", "dev", "snapshot" };

    /// <summary>Build tags that are not part of the version ("5.7.44-log", "1.2.3+build5").</summary>
    private static readonly HashSet<string> Ignored = new(StringComparer.OrdinalIgnoreCase) { "log", "release", "final", "ga", "stable" };

    public static int Compare(string left, string right)
    {
        var a = Tokens(left);
        var b = Tokens(right);
        var n = Math.Max(a.Count, b.Count);
        for (var i = 0; i < n; i++)
        {
            Token? x = i < a.Count ? a[i] : null;
            Token? y = i < b.Count ? b[i] : null;
            var c = CompareToken(x, y);
            if (c != 0) return c;
        }

        return 0;
    }

    public static bool AreEqual(string left, string right) => Compare(left, right) == 0;

    /// <summary>
    /// True when <paramref name="detected"/> is less precise than <paramref name="bound"/> and agrees with it as far as it
    /// goes ("2.4" against "2.4.52") – the real version could lie on either side of the bound.
    /// </summary>
    public static bool IsAmbiguousAgainst(string detected, string bound)
    {
        var d = Tokens(detected);
        var b = Tokens(bound);
        if (d.Count >= b.Count) return false;
        for (var i = 0; i < d.Count; i++)
        {
            if (CompareToken(d[i], b[i]) != 0) return false;
        }

        // "8.9" vs "8.9.0" is not ambiguous – the remaining components are zeros.
        return b.Skip(d.Count).Any(t => t is not { IsNumber: true, Number: 0 });
    }

    /// <summary>A version that can be compared at all: starts with a digit.</summary>
    public static bool IsComparable(string? version) => !string.IsNullOrWhiteSpace(version) && char.IsAsciiDigit(version.Trim()[0]);

    private readonly record struct Token(bool IsNumber, long Number, string Text);

    private static List<Token> Tokens(string version)
    {
        var tokens = new List<Token>();
        foreach (Match m in TokenRx().Matches(version.Trim()))
        {
            var text = m.Value;
            if (char.IsAsciiDigit(text[0]))
            {
                tokens.Add(new Token(true, long.TryParse(text.Length > 18 ? text[..18] : text, out var n) ? n : long.MaxValue, text));
            }
            else if (!Ignored.Contains(text))
            {
                tokens.Add(new Token(false, 0, text.ToLowerInvariant()));
            }
        }

        // Trailing zeros are insignificant: "1.0.0" == "1.0" == "1".
        while (tokens.Count > 1 && tokens[^1] is { IsNumber: true, Number: 0 }) tokens.RemoveAt(tokens.Count - 1);
        return tokens;
    }

    private static int CompareToken(Token? x, Token? y)
    {
        if (x is null && y is null) return 0;
        if (x is null) return -Weight(y!.Value);
        if (y is null) return Weight(x.Value);

        var a = x.Value;
        var b = y.Value;
        if (a.IsNumber && b.IsNumber) return a.Number.CompareTo(b.Number);
        if (a.IsNumber) return PreRelease.Contains(b.Text) ? 1 : -1;
        if (b.IsNumber) return PreRelease.Contains(a.Text) ? -1 : 1;

        var aPre = PreRelease.Contains(a.Text);
        var bPre = PreRelease.Contains(b.Text);
        if (aPre != bPre) return aPre ? -1 : 1;
        return string.CompareOrdinal(a.Text, b.Text);
    }

    /// <summary>How an extra component changes a version that otherwise ends: zeros nothing, pre-release lowers, the rest raises.</summary>
    private static int Weight(Token t) => t.IsNumber ? (t.Number == 0 ? 0 : 1) : PreRelease.Contains(t.Text) ? -1 : 1;

    [GeneratedRegex(@"\d+|[A-Za-z]+")]
    private static partial Regex TokenRx();
}
