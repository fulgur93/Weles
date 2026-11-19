using System.Text;

namespace Weles.Core.Vulnerabilities;

/// <summary>The parts of a CPE 2.3 formatted string WELES matches on. "*" = any value, "-" = not applicable.</summary>
public sealed record CpeName(string Part, string Vendor, string Product, string Version, string Update)
{
    public const string Any = "*";
    public const string NotApplicable = "-";

    public bool HasSpecificVersion => Version is not (Any or NotApplicable) && Version.Length > 0;
    public bool HasSpecificUpdate => Update is not (Any or NotApplicable) && Update.Length > 0;

    /// <summary>Version as products print it: NVD stores OpenSSH "8.9p1" as version "8.9", update "p1".</summary>
    public string? FullVersion => !HasSpecificVersion ? null : HasSpecificUpdate ? Version + Update : Version;

    /// <summary>Parses "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*" (backslash escapes are honoured). Null when malformed.</summary>
    public static CpeName? Parse(string? cpe)
    {
        if (string.IsNullOrWhiteSpace(cpe) || !cpe.StartsWith("cpe:2.3:", StringComparison.OrdinalIgnoreCase)) return null;

        var fields = Split(cpe);
        if (fields.Count < 7) return null;
        var part = fields[2].ToLowerInvariant();
        if (part is not ("a" or "o" or "h")) return null;
        return new CpeName(part, fields[3].ToLowerInvariant(), fields[4].ToLowerInvariant(), fields[5].ToLowerInvariant(), fields[6].ToLowerInvariant());
    }

    private static List<string> Split(string cpe)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        for (var i = 0; i < cpe.Length; i++)
        {
            var c = cpe[i];
            if (c == '\\' && i + 1 < cpe.Length)
            {
                current.Append(cpe[++i]);
            }
            else if (c == ':')
            {
                fields.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        fields.Add(current.ToString());
        return fields;
    }
}
