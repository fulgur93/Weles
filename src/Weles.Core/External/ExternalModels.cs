using System.Globalization;
using System.Net;
using Weles.Core.Enums;
using Weles.Core.Networking;

namespace Weles.Core.External;

/// <summary>One DNS record as shown to the user and stored in the analysis snapshot.</summary>
public sealed record DnsRecordView(string Name, string Type, string Value, uint Ttl);

/// <summary>A host name of the analysed domain and how it resolves.</summary>
/// <param name="Sources">Where the name came from: "DNS", "CT", "MX", "NS", "CNAME", "użytkownik", "certyfikat TLS".</param>
/// <param name="Cname">Last CNAME target in the chain, if any.</param>
/// <param name="DanglingCname">The name points (CNAME) to a name that does not exist (NXDOMAIN).</param>
/// <param name="MatchesWildcard">All addresses equal the wildcard answer – the name may not really exist.</param>
public sealed record ExternalHostView(
    string Name,
    IReadOnlyList<string> Addresses,
    string? Cname,
    bool Resolves,
    bool DanglingCname,
    bool MatchesWildcard,
    IReadOnlyList<string> Sources);

/// <summary>A certificate found in Certificate Transparency logs (public data, nothing was contacted on the domain).</summary>
public sealed record CtCertificateView(long Id, string CommonName, IReadOnlyList<string> Names, string Issuer, DateTime NotBefore, DateTime NotAfter);

/// <summary>Everything a passive analysis collected. Stored as JSON so later rule changes can re-evaluate old analyses.</summary>
public sealed record ExternalSnapshot(
    string Domain,
    DateTime CollectedAt,
    IReadOnlyList<string> Resolvers,
    IReadOnlyList<DnsRecordView> Records,
    IReadOnlyList<ExternalHostView> Hosts,
    IReadOnlyList<CtCertificateView> Certificates,
    bool CtQueried,
    string? CtError,
    IReadOnlyList<string> WildcardAddresses,
    int SkippedNames,
    IReadOnlyList<string> Notes)
{
    public IEnumerable<DnsRecordView> OfType(string type) => Records.Where(r => r.Type == type);

    /// <summary>TXT records of the domain itself starting with "v=spf1".</summary>
    public IReadOnlyList<string> SpfRecords => Records.Where(r => r.Type == "TXT" && r.Name == Domain && r.Value.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)
        && (r.Value.Length == 6 || r.Value[6] == ' ')).Select(r => r.Value).ToList();

    public IReadOnlyList<string> DmarcRecords => Records.Where(r => r.Type == "TXT" && r.Name == "_dmarc." + Domain).Select(r => r.Value)
        .Where(v => v.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)).ToList();
}

/// <summary>A finding of the passive analysis with its evidence. Never a confirmed vulnerability – a configuration observation.</summary>
public sealed record ExternalFinding(string Code, RiskLevel Level, string Title, string Evidence, string Recommendation, string? Host = null);

public static class DomainNames
{
    private static readonly string[] InternalSuffixes = ["local", "lan", "home", "internal", "localdomain", "arpa", "corp", "intranet", "test", "invalid", "localhost", "example"];

    /// <summary>
    /// Validates a domain the user wants to analyse externally: a registrable public name (IDN converted to its ASCII form),
    /// not an address and not an internal-only suffix.
    /// </summary>
    public static bool TryNormalize(string? input, out string domain, out string? error)
    {
        domain = "";
        var value = (input ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        if (value.StartsWith("*.", StringComparison.Ordinal)) value = value[2..];
        if (value.Length == 0)
        {
            error = "Podaj domenę.";
            return false;
        }

        if (value.Contains("://") || value.Contains('/') || value.Contains('@') || value.Contains(' '))
        {
            error = "Podaj samą nazwę domeny, np. firma.pl (bez http://, ścieżki i adresu e‑mail).";
            return false;
        }

        try
        {
            value = new IdnMapping().GetAscii(value);
        }
        catch (ArgumentException)
        {
            error = $"Nieprawidłowa nazwa domeny: {input}";
            return false;
        }

        if (IPAddress.TryParse(value, out _))
        {
            error = "To jest adres IP – dodaj go jako adres publiczny.";
            return false;
        }

        if (!TargetParser.TryParse(value, out var parsed, out _) || parsed.Kind != ScanTargetEntryKind.Domain || !value.Contains('.'))
        {
            error = $"Nieprawidłowa nazwa domeny: {input}";
            return false;
        }

        var tld = value[(value.LastIndexOf('.') + 1)..];
        if (InternalSuffixes.Contains(tld) || tld.All(char.IsDigit))
        {
            error = $"Domena {value} nie jest publiczna (.{tld}) – analiza zewnętrzna dotyczy domen widocznych w Internecie.";
            return false;
        }

        domain = value;
        error = null;
        return true;
    }

    /// <summary>True for the domain itself and its subdomains ("a.b.firma.pl" is within "firma.pl", "zlafirma.pl" is not).</summary>
    public static bool IsWithin(string name, string root) =>
        name.Equals(root, StringComparison.OrdinalIgnoreCase) || name.EndsWith("." + root, StringComparison.OrdinalIgnoreCase);

    /// <summary>A host name from an untrusted source (CT log, DNS answer): lower-case, without "*." and the trailing dot; null when invalid.</summary>
    public static string? CleanHostName(string? raw)
    {
        var value = (raw ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        while (value.StartsWith("*.", StringComparison.Ordinal)) value = value[2..];
        if (value.Length is 0 or > 253 || value.Contains('*')) return null;
        return TargetParser.TryParse(value, out var parsed, out _) && parsed.Kind == ScanTargetEntryKind.Domain ? value : null;
    }

    /// <summary>Validates a public IPv4/IPv6 address the user wants to analyse.</summary>
    public static bool TryParsePublicAddress(string? input, out IPAddress address, out string? error)
    {
        address = IPAddress.None;
        if (!IPAddress.TryParse((input ?? "").Trim(), out var parsed))
        {
            error = $"Nieprawidłowy adres IP: {input}";
            return false;
        }

        if (AddressClassifier.Classify(parsed) != AddressScope.Public)
        {
            error = $"Adres {parsed} nie jest publiczny – adresy z sieci lokalnej skanuje się w module Wykrywanie sieci.";
            return false;
        }

        address = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        error = null;
        return true;
    }
}
