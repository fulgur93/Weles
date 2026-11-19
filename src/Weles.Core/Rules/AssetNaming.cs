using System.Text.RegularExpressions;

namespace Weles.Core.Rules;

public static partial class AssetNaming
{
    /// <summary>Vendor text used for locally administered (randomized) MAC addresses.</summary>
    public const string RandomMacVendor = "Adres losowy / administrowany lokalnie";

    public const int MaxNameLength = 255;

    /// <summary>What to call a device without a host name: its model if it disclosed one, otherwise the short vendor name.</summary>
    public static string? Label(string? model, string? vendor) =>
        !string.IsNullOrWhiteSpace(model) ? model.Trim() : ShortVendor(vendor);

    /// <summary>"TP-LINK TECHNOLOGIES CO.,LTD." → "TP-LINK", "Wistron InfoComm(Chongqing)Co.,Ltd." → "Wistron InfoComm".</summary>
    public static string? ShortVendor(string? vendor)
    {
        if (string.IsNullOrWhiteSpace(vendor) || vendor == RandomMacVendor) return vendor;
        var name = Parenthesised().Replace(vendor, " ");
        string previous;
        do
        {
            previous = name;
            name = CorporateSuffix().Replace(name, "").Trim().TrimEnd(',', '.', ' ');
        } while (name != previous && name.Length > 0);

        return name.Length >= 2 ? name : vendor.Trim();
    }

    /// <summary>Automatic name: host name, otherwise "label (IP)", otherwise the IP address.</summary>
    public static string AutoName(string? hostname, string? vendor, string? ipAddress)
    {
        var name = !string.IsNullOrWhiteSpace(hostname) ? hostname
            : !string.IsNullOrWhiteSpace(vendor) && vendor != RandomMacVendor ? $"{vendor} ({ipAddress})"
            : ipAddress ?? "Nieznane urządzenie";
        return name.Length > MaxNameLength ? name[..MaxNameLength] : name;
    }

    public static string DisplayName(string? customName, string? hostname, string? vendor, string? ipAddress) =>
        string.IsNullOrWhiteSpace(customName) ? AutoName(hostname, vendor, ipAddress) : customName.Trim();

    [GeneratedRegex(@"\([^)]*\)")] private static partial Regex Parenthesised();

    [GeneratedRegex(@"[\s,]*\b(co\.?,?\s*ltd\.?|ltd\.?|inc\.?|incorporated|corp\.?|corporation|llc|gmbh|ag|s\.?a\.?|b\.?v\.?|limited|company|co\.?|technologies|technology|electronics)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex CorporateSuffix();
}
