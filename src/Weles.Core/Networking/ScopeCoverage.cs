using System.Net;
using System.Text.Json;

namespace Weles.Core.Networking;

/// <summary>
/// Which addresses a past scan covered, rebuilt from its scope snapshot. Domain entries cannot be re-evaluated
/// without DNS, so for them coverage is established only by an actual observation in that scan.
/// </summary>
public sealed class ScopeCoverage
{
    private readonly List<Ipv4Range> _include = [];
    private readonly List<Ipv4Range> _exclude = [];
    private readonly HashSet<IPAddress> _includeV6 = [];
    private readonly HashSet<IPAddress> _excludeV6 = [];

    private sealed record SnapshotEntry(string Value, bool IsExclusion);

    public static ScopeCoverage FromSnapshot(string? snapshotJson)
    {
        var coverage = new ScopeCoverage();
        if (string.IsNullOrWhiteSpace(snapshotJson)) return coverage;

        List<SnapshotEntry>? entries;
        try
        {
            entries = JsonSerializer.Deserialize<List<SnapshotEntry>>(snapshotJson);
        }
        catch (JsonException)
        {
            return coverage;
        }

        foreach (var entry in entries ?? [])
        {
            if (!TargetParser.TryParse(entry.Value, out var parsed, out _)) continue;
            if ((entry.IsExclusion ? parsed.ExclusionRange : parsed.Ipv4Range) is { } range)
            {
                (entry.IsExclusion ? coverage._exclude : coverage._include).Add(range);
            }
            else if (parsed.Ipv6Address is { } v6)
            {
                (entry.IsExclusion ? coverage._excludeV6 : coverage._includeV6).Add(v6);
            }
        }

        return coverage;
    }

    public bool Covers(string? ipAddress) => IPAddress.TryParse(ipAddress, out var a) && Covers(a);

    public bool Covers(IPAddress address)
    {
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var v = Ipv4.ToUInt(address);
            return _include.Any(r => r.Contains(v)) && !_exclude.Any(r => r.Contains(v));
        }

        return _includeV6.Contains(address) && !_excludeV6.Contains(address);
    }
}
