using Weles.Core.Entities;
using Weles.Core.Enums;

namespace Weles.Core.Rules;

public sealed record AssetChange(AssetChangeKind Kind, string Description, int? Port = null);

/// <summary>One observation of an asset and the TCP ports its scan checked (null = unknown, treated as "every port").</summary>
public sealed record PortObservation(DiscoveredHost Host, IReadOnlySet<int>? CheckedPorts);

/// <param name="Changes">Changes per observation, in the order given (the first observation has none).</param>
/// <param name="CurrentPorts">Last known open ports: from the latest scan that checked each port.</param>
public sealed record ObservationHistory(IReadOnlyList<IReadOnlyList<AssetChange>> Changes, IReadOnlyList<DiscoveredPort> CurrentPorts);

/// <summary>Differences between observations of the same asset (ports, services, versions, certificates, identity).</summary>
public static class ObservationComparer
{
    /// <summary>
    /// Replays observations in chronological order keeping the last known state of every port. A port the scan did not
    /// check (a quick scan after a standard one) keeps its state: it is neither "closed" then nor "newly opened" later.
    /// </summary>
    public static ObservationHistory Replay(IReadOnlyList<PortObservation> observations)
    {
        var known = new Dictionary<(int Port, TransportProtocol Protocol), DiscoveredPort>();
        var all = new List<IReadOnlyList<AssetChange>>(observations.Count);
        for (var i = 0; i < observations.Count; i++)
        {
            var (host, checkedPorts) = observations[i];
            all.Add(i == 0 ? [] : Changes(observations[i - 1].Host, host, known, checkedPorts));
            foreach (var key in known.Keys.Where(k => IsChecked(k, checkedPorts)).ToList()) known.Remove(key);
            foreach (var port in host.Ports.Where(p => p.State == PortState.Open)) known[(port.Port, port.Protocol)] = port;
        }

        return new ObservationHistory(all, known.OrderBy(k => k.Key.Port).Select(k => k.Value).ToList());
    }

    /// <summary>Compares two observations whose scans checked the same ports.</summary>
    public static IReadOnlyList<AssetChange> Compare(DiscoveredHost previous, DiscoveredHost current) =>
        Changes(previous, current, previous.Ports.Where(p => p.State == PortState.Open).ToDictionary(p => (p.Port, p.Protocol)), checkedPorts: null);

    private static bool IsChecked((int Port, TransportProtocol Protocol) key, IReadOnlySet<int>? checkedPorts) =>
        checkedPorts is null || key.Protocol != TransportProtocol.Tcp || checkedPorts.Contains(key.Port);

    private static List<AssetChange> Changes(DiscoveredHost previous, DiscoveredHost current,
        IReadOnlyDictionary<(int Port, TransportProtocol Protocol), DiscoveredPort> before, IReadOnlySet<int>? checkedPorts)
    {
        var changes = new List<AssetChange>();

        if (previous.IpAddress != current.IpAddress)
            changes.Add(new(AssetChangeKind.AddressChanged, $"Adres IP: {previous.IpAddress} → {current.IpAddress}"));
        if (!string.Equals(previous.Hostname, current.Hostname, StringComparison.OrdinalIgnoreCase) && current.Hostname is not null)
            changes.Add(new(AssetChangeKind.HostnameChanged, $"Nazwa hosta: {previous.Hostname ?? "—"} → {current.Hostname}"));
        if (previous.MacAddress is not null && current.MacAddress is not null && previous.MacAddress != current.MacAddress)
            changes.Add(new(AssetChangeKind.MacChanged, $"Adres MAC: {previous.MacAddress} → {current.MacAddress}"));
        if (previous.AssetTypeGuess != current.AssetTypeGuess && current.AssetTypeGuess != AssetType.Unknown && previous.AssetTypeGuess != AssetType.Unknown)
            changes.Add(new(AssetChangeKind.TypeChanged, $"Rozpoznany typ: {previous.AssetTypeGuess} → {current.AssetTypeGuess}"));

        var after = current.Ports.Where(p => p.State == PortState.Open).ToDictionary(p => (p.Port, p.Protocol));

        foreach (var (key, port) in after.Where(a => !before.ContainsKey(a.Key)).OrderBy(a => a.Key.Port))
            changes.Add(new(AssetChangeKind.PortOpened, $"Nowy otwarty port {key.Port}/{Proto(key.Protocol)}{Describe(port.Service)}", key.Port));

        // Ports open in the current observation are checked by definition (e.g. announced over mDNS).
        foreach (var (key, port) in before.Where(b => !after.ContainsKey(b.Key) && IsChecked(b.Key, checkedPorts)).OrderBy(b => b.Key.Port))
            changes.Add(new(AssetChangeKind.PortClosed, $"Port {key.Port}/{Proto(key.Protocol)} nie jest już otwarty{Describe(port.Service)}", key.Port));

        foreach (var (key, now) in after.Where(a => before.ContainsKey(a.Key)).OrderBy(a => a.Key.Port))
        {
            var was = before[key].Service;
            var cur = now.Service;
            if (was is null || cur is null) continue;

            if (was.Product is not null && cur.Product is not null && !string.Equals(was.Product, cur.Product, StringComparison.OrdinalIgnoreCase))
            {
                changes.Add(new(AssetChangeKind.ServiceChanged, $"Port {key.Port}: {was.Product} → {cur.Product}", key.Port));
            }
            else if (was.Version is not null && cur.Version is not null && was.Version != cur.Version)
            {
                changes.Add(new(AssetChangeKind.VersionChanged, $"Port {key.Port}: {cur.Product ?? cur.ServiceName} {was.Version} → {cur.Version}", key.Port));
            }

            var oldCert = was.Certificates.FirstOrDefault();
            var newCert = cur.Certificates.FirstOrDefault();
            if (oldCert is not null && newCert is not null && oldCert.Thumbprint != newCert.Thumbprint)
            {
                changes.Add(new(AssetChangeKind.CertificateChanged, $"Port {key.Port}: nowy certyfikat TLS (ważny do {newCert.NotAfter:yyyy-MM-dd})", key.Port));
            }
        }

        return changes;
    }

    private static string Proto(TransportProtocol p) => p == TransportProtocol.Tcp ? "tcp" : "udp";

    private static string Describe(DiscoveredService? s) =>
        s is null ? "" : s.Product is not null ? $" ({s.Product}{(s.Version is null ? "" : " " + s.Version)})" : s.ServiceName is not null ? $" ({s.ServiceName})" : "";
}
