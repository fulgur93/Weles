using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Weles.Core.Enums;

namespace Weles.Core.Networking;

/// <param name="Ipv4Range">Addresses to scan (for CIDR without network and broadcast addresses).</param>
/// <param name="FullIpv4Range">Every address covered by the entry – used for exclusions.</param>
public sealed record ParsedTarget(ScanTargetEntryKind Kind, string Normalized, Ipv4Range? Ipv4Range, IPAddress? Ipv6Address, string? Domain, Ipv4Range? FullIpv4Range = null)
{
    public Ipv4Range? ExclusionRange => FullIpv4Range ?? Ipv4Range;
}

/// <summary>Parses scope entries: IPv4 / IPv6 address, IPv4 CIDR, IPv4 range ("a.b.c.d-e.f.g.h" or "a.b.c.d-200"), domain.</summary>
public static partial class TargetParser
{
    /// <summary>Largest accepted network. Larger networks must be split deliberately.</summary>
    public const int MinimumPrefix = 16;

    public const int MaximumRangeSize = 65_536;

    public static bool TryParse(string? raw, [NotNullWhen(true)] out ParsedTarget? target, out string? error)
    {
        target = null;
        error = null;
        var value = raw?.Trim() ?? "";
        if (value.Length == 0)
        {
            error = "Pusty wpis.";
            return false;
        }

        if (value.Length > 255)
        {
            error = "Wpis jest za długi.";
            return false;
        }

        if (value.Contains('/'))
        {
            return TryParseCidr(value, out target, out error);
        }

        if (value.Contains('-') && Ipv4Prefix().IsMatch(value))
        {
            return TryParseRange(value, out target, out error);
        }

        if (Ipv4Pattern().IsMatch(value))
        {
            if (!TryParseIpv4(value, out var v4))
            {
                error = $"Nieprawidłowy adres IPv4: {value}";
                return false;
            }

            var n = Ipv4.ToUInt(v4);
            target = new ParsedTarget(ScanTargetEntryKind.IpAddress, v4.ToString(), new Ipv4Range(n, n), null, null);
            return true;
        }

        if (value.Contains(':'))
        {
            if (IPAddress.TryParse(value, out var v6) && v6.AddressFamily == AddressFamily.InterNetworkV6)
            {
                target = new ParsedTarget(ScanTargetEntryKind.IpAddress, v6.ToString(), null, v6, null);
                return true;
            }

            error = $"Nieprawidłowy adres IPv6: {value}";
            return false;
        }

        var domain = value.TrimEnd('.').ToLowerInvariant();
        if (DomainPattern().IsMatch(domain) && domain.Any(char.IsLetter))
        {
            target = new ParsedTarget(ScanTargetEntryKind.Domain, domain, null, null, domain);
            return true;
        }

        error = $"Nierozpoznany wpis: {value} (oczekiwano IP, CIDR, zakresu lub domeny).";
        return false;
    }

    private static bool TryParseCidr(string value, out ParsedTarget? target, out string? error)
    {
        target = null;
        var parts = value.Split('/');
        if (parts.Length != 2 || !int.TryParse(parts[1], out var prefix))
        {
            error = $"Nieprawidłowy zapis CIDR: {value}";
            return false;
        }

        if (!Ipv4Pattern().IsMatch(parts[0]) || !TryParseIpv4(parts[0], out var address))
        {
            error = parts[0].Contains(':')
                ? "Zakresy CIDR IPv6 nie są obsługiwane – podaj pojedyncze adresy IPv6."
                : $"Nieprawidłowy adres w CIDR: {value}";
            return false;
        }

        if (prefix is < 0 or > 32)
        {
            error = $"Prefiks musi mieć wartość 0–32: {value}";
            return false;
        }

        if (prefix < MinimumPrefix)
        {
            error = $"Zakres {value} jest za duży – maksymalnie /{MinimumPrefix}. Podziel go na mniejsze sieci.";
            return false;
        }

        var n = Ipv4.ToUInt(address);
        target = new ParsedTarget(ScanTargetEntryKind.Cidr, Ipv4.CidrNotation(n, prefix), Ipv4.CidrRange(n, prefix, hostsOnly: true), null, null, Ipv4.CidrRange(n, prefix, hostsOnly: false));
        error = null;
        return true;
    }

    private static bool TryParseRange(string value, out ParsedTarget? target, out string? error)
    {
        target = null;
        var parts = value.Split('-', 2, StringSplitOptions.TrimEntries);
        if (!TryParseIpv4(parts[0], out var startAddress))
        {
            error = $"Nieprawidłowy początek zakresu: {value}";
            return false;
        }

        var start = Ipv4.ToUInt(startAddress);
        uint end;
        if (byte.TryParse(parts[1], out var lastOctet))
        {
            end = (start & 0xFFFFFF00) | lastOctet;
        }
        else if (Ipv4Pattern().IsMatch(parts[1]) && TryParseIpv4(parts[1], out var endAddress))
        {
            end = Ipv4.ToUInt(endAddress);
        }
        else
        {
            error = $"Nieprawidłowy koniec zakresu: {value}";
            return false;
        }

        if (end < start)
        {
            error = $"Koniec zakresu jest mniejszy niż początek: {value}";
            return false;
        }

        var range = new Ipv4Range(start, end);
        if (range.Count > MaximumRangeSize)
        {
            error = $"Zakres {value} obejmuje {range.Count} adresów – maksymalnie {MaximumRangeSize}.";
            return false;
        }

        target = new ParsedTarget(ScanTargetEntryKind.IpRange, range.ToString(), range, null, null);
        error = null;
        return true;
    }

    private static bool TryParseIpv4(string value, out IPAddress address)
    {
        address = IPAddress.None;
        var octets = value.Split('.');
        if (octets.Length != 4 || octets.Any(o => o.Length is 0 or > 3 || !byte.TryParse(o, out _)))
        {
            return false;
        }

        address = new IPAddress(octets.Select(byte.Parse).ToArray());
        return true;
    }

    /// <summary>Splits free-form input (lines, commas, semicolons, spaces) into entries.</summary>
    public static IEnumerable<string> SplitEntries(string? text) =>
        (text ?? "").Split(['\n', '\r', ',', ';', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(e => !e.StartsWith('#'));

    [GeneratedRegex(@"^\d{1,3}(\.\d{1,3}){3}$")]
    private static partial Regex Ipv4Pattern();

    [GeneratedRegex(@"^\d{1,3}(\.\d{1,3}){3}\s*-")]
    private static partial Regex Ipv4Prefix();

    [GeneratedRegex(@"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")]
    private static partial Regex DomainPattern();
}
