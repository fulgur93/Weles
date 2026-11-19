using System.Text.RegularExpressions;

namespace Weles.Core.Rules;

/// <summary>A hardware model named by the device itself (HTTP realm, UPnP Server header, page title).</summary>
public sealed record DetectedModel(string Name, string? HardwareVersion);

/// <summary>
/// Extracts hardware model names that consumer devices disclose without logging in. Only explicit vendor patterns are
/// recognised – a model is evidence for later vulnerability matching, so a guess would be worse than nothing.
/// </summary>
public static partial class DeviceModel
{
    public static DetectedModel? Detect(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        // UPnP / Server header: "TL-WR841N/9.0" – the number after the slash is the hardware revision.
        if (TpLinkTokenRx().Match(text) is { Success: true } token)
        {
            return new DetectedModel($"TP-Link {token.Groups[1].Value.ToUpperInvariant()}", token.Groups[2].Success ? token.Groups[2].Value : null);
        }

        // Basic-auth realm or title: "TP-LINK Wireless N Router WR841N".
        if (TpLinkRealmRx().Match(text) is { Success: true } realm)
        {
            return new DetectedModel($"TP-Link TL-{realm.Groups[1].Value.ToUpperInvariant()}", null);
        }

        if (TpLinkArcherRx().Match(text) is { Success: true } archer)
        {
            return new DetectedModel($"TP-Link Archer {archer.Groups[1].Value.ToUpperInvariant()}", null);
        }

        return null;
    }

    [GeneratedRegex(@"\b(TL-(?:WR|WA|MR|WDR|WPA|SG|SF)\d{3,4}[A-Z]{0,3})(?:/(\d+(?:\.\d+)?))?\b", RegexOptions.IgnoreCase)]
    private static partial Regex TpLinkTokenRx();

    [GeneratedRegex(@"TP-?LINK\b[^\n""]{0,60}?\b((?:WR|WA|MR|WDR)\d{3,4}[A-Z]{0,3})\b", RegexOptions.IgnoreCase)]
    private static partial Regex TpLinkRealmRx();

    [GeneratedRegex(@"\bArcher[ _-]?([A-Z]{1,2}\d{1,4}[A-Z]?)\b", RegexOptions.IgnoreCase)]
    private static partial Regex TpLinkArcherRx();
}
