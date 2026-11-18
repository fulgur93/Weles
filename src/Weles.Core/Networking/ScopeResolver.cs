using System.Net;
using System.Net.Sockets;

namespace Weles.Core.Networking;

public sealed record ScopeEntry(string Value, bool IsExclusion);

public sealed record ScopeResolution(IReadOnlyList<IPAddress> Addresses, IReadOnlyList<string> Warnings, IReadOnlyList<string> Errors, int SkippedPublic)
{
    public bool IsValid => Errors.Count == 0 && Addresses.Count > 0;
}

/// <summary>
/// Turns scope entries into the concrete list of addresses that may be scanned.
/// Exclusions always win, public addresses are dropped unless explicitly allowed,
/// reserved/multicast addresses are never scanned.
/// </summary>
public static class ScopeResolver
{
    public delegate Task<IReadOnlyList<IPAddress>> DomainResolver(string domain, CancellationToken cancellationToken);

    private const long MaterializationLimit = 1_000_000;

    public static async Task<ScopeResolution> ResolveAsync(
        IEnumerable<ScopeEntry> entries,
        bool allowPublicAddresses,
        int maxHosts,
        DomainResolver resolveDomain,
        CancellationToken cancellationToken = default)
    {
        var warnings = new List<string>();
        var errors = new List<string>();
        var includeV4 = new List<Ipv4Range>();
        var excludeV4 = new List<Ipv4Range>();
        var includeV6 = new HashSet<IPAddress>();
        var excludeV6 = new HashSet<IPAddress>();

        foreach (var entry in entries)
        {
            if (!TargetParser.TryParse(entry.Value, out var parsed, out var error))
            {
                errors.Add(error!);
                continue;
            }

            var v4 = entry.IsExclusion ? excludeV4 : includeV4;
            var v6 = entry.IsExclusion ? excludeV6 : includeV6;

            if ((entry.IsExclusion ? parsed.ExclusionRange : parsed.Ipv4Range) is { } range)
            {
                v4.Add(range);
            }
            else if (parsed.Ipv6Address is { } address6)
            {
                v6.Add(address6);
            }
            else if (parsed.Domain is { } domain)
            {
                IReadOnlyList<IPAddress> resolved;
                try
                {
                    resolved = await resolveDomain(domain, cancellationToken);
                }
                catch (SocketException ex)
                {
                    warnings.Add($"Nie udało się rozwiązać domeny {domain}: {ex.Message}");
                    continue;
                }

                if (resolved.Count == 0)
                {
                    warnings.Add($"Domena {domain} nie ma rekordów A/AAAA.");
                }

                foreach (var a in resolved)
                {
                    var address = a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a;
                    if (address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        var n = Ipv4.ToUInt(address);
                        v4.Add(new Ipv4Range(n, n));
                    }
                    else
                    {
                        v6.Add(address);
                    }
                }
            }
        }

        if (includeV4.Sum(r => r.Count) > MaterializationLimit)
        {
            errors.Add("Zakres jest zbyt duży do przetworzenia.");
        }

        if (errors.Count > 0)
        {
            return new ScopeResolution([], warnings, errors, 0);
        }

        var addresses = new SortedSet<uint>();
        foreach (var range in includeV4)
        {
            for (long i = range.Start; i <= range.End; i++)
            {
                addresses.Add((uint)i);
            }
        }

        addresses.RemoveWhere(a => excludeV4.Any(r => r.Contains(a)));
        includeV6.ExceptWith(excludeV6);

        var result = new List<IPAddress>();
        var skippedPublic = 0;
        var skippedReserved = 0;
        foreach (var address in addresses.Select(Ipv4.FromUInt).Concat(includeV6))
        {
            switch (AddressClassifier.Classify(address))
            {
                case AddressScope.Reserved:
                    skippedReserved++;
                    break;
                case AddressScope.Public when !allowPublicAddresses:
                    skippedPublic++;
                    break;
                default:
                    result.Add(address);
                    break;
            }
        }

        if (skippedPublic > 0)
        {
            warnings.Add($"Pominięto {skippedPublic} adres(ów) publicznych – zakres nie ma zgody na skanowanie adresów publicznych.");
        }

        if (skippedReserved > 0)
        {
            warnings.Add($"Pominięto {skippedReserved} adres(ów) zarezerwowanych lub multicast.");
        }

        if (result.Count > maxHosts)
        {
            errors.Add($"Zakres obejmuje {result.Count} adresów, a limit to {maxHosts}. Zawęź zakres lub dodaj wykluczenia.");
            return new ScopeResolution([], warnings, errors, skippedPublic);
        }

        if (result.Count == 0)
        {
            errors.Add("Po zastosowaniu wykluczeń i ograniczeń zakres nie zawiera żadnego adresu do skanowania.");
        }

        return new ScopeResolution(result, warnings, errors, skippedPublic);
    }
}
