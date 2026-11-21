using System.Net;

namespace Weles.Core.Topology;

/// <summary>What a link on the map rests on – from the strongest observation to a plain inference.</summary>
public enum LinkKind
{
    /// <summary>Only the address and the gateway – "same network", nothing on the wire confirmed it.</summary>
    Inferred = 0,
    /// <summary>The device's MAC was in this computer's ARP table – observed on the same layer-2 segment.</summary>
    ArpNeighbour = 1,
    /// <summary>The ICMP reply arrived with an unchanged TTL (64/128/255) – observed: no router in between.</summary>
    TtlDirect = 2,
    /// <summary>The reply's TTL was lowered – observed: about N routers in between, so "same LAN" is not true.</summary>
    TtlRouted = 3,
    /// <summary>Traceroute listed the routers on the way – observed path.</summary>
    Traceroute = 4
}

/// <param name="Hops">Routers between the WELES computer and the device (0 – direct), when known.</param>
/// <param name="Path">Router addresses that answered on the way (traceroute), in order; the device itself not included.</param>
public sealed record LinkEvidence(LinkKind Kind, int? Hops, IReadOnlyList<string> Path, string Reason)
{
    public bool Observed => Kind != LinkKind.Inferred;
    public bool Routed => Hops is > 0;
}

/// <summary>Facts about the latest observation of a device, as stored by the scanner.</summary>
/// <param name="ViaArp">The device was found (also) through this computer's ARP table.</param>
/// <param name="Ttl">TTL of the ICMP echo reply; null when it did not answer ping.</param>
/// <param name="TracePath">Traceroute result: router addresses on the way and the target last, when it was reached.</param>
public sealed record LinkFacts(string? Ip, bool ViaArp, string? Mac, int? Ttl, IReadOnlyList<string>? TracePath, bool IsLocalMachine = false);

public static class TopologyEvidence
{
    /// <summary>Common initial TTLs (Linux/macOS/Android 64, Windows 128, network gear 255).</summary>
    private static readonly int[] InitialTtls = [64, 128, 255];

    /// <summary>Routers between sender and receiver estimated from a reply's TTL; null without a TTL.</summary>
    public static int? HopsFromTtl(int? ttl)
    {
        if (ttl is not { } t || t is <= 0 or > 255) return null;
        return InitialTtls.First(i => i >= t) - t;
    }

    /// <summary>The strongest evidence available for the link of one device; traceroute beats TTL beats ARP beats inference.</summary>
    public static LinkEvidence For(LinkFacts f)
    {
        if (f.IsLocalMachine) return new LinkEvidence(LinkKind.ArpNeighbour, 0, [], "komputer, na którym działa WELES");

        if (f.TracePath is { Count: > 0 } path)
        {
            var reached = f.Ip is not null && path[^1] == f.Ip;
            var routers = (reached ? path.Take(path.Count - 1) : path).Where(p => p != f.Ip).ToList();
            if (reached || routers.Count > 0)
            {
                var hops = reached ? routers.Count : (int?)null;
                var how = routers.Count == 0 ? "traceroute: bez routera po drodze" : $"traceroute: przez {string.Join(" → ", routers)}";
                return new LinkEvidence(LinkKind.Traceroute, hops, routers, reached ? how : how + " (cel nie odpowiedział na końcu trasy)");
            }
        }

        var ttlHops = HopsFromTtl(f.Ttl);
        if (ttlHops is > 0)
        {
            return new LinkEvidence(LinkKind.TtlRouted, ttlHops, [],
                $"TTL odpowiedzi {f.Ttl} – ok. {ttlHops} {Routers(ttlHops.Value)} po drodze; to nie ten sam segment");
        }

        if (f.ViaArp && f.Mac is not null)
        {
            return new LinkEvidence(LinkKind.ArpNeighbour, 0, [], $"MAC {f.Mac} w tablicy ARP – ten sam segment sieci (warstwa 2) co komputer z WELES");
        }

        if (ttlHops == 0)
        {
            return new LinkEvidence(LinkKind.TtlDirect, 0, [], $"TTL odpowiedzi {f.Ttl} bez zmian – bez routera po drodze");
        }

        return new LinkEvidence(LinkKind.Inferred, null, [], "wywnioskowane z adresu i bramy – nie zaobserwowano (brak ARP, TTL i traceroute)");
    }

    private static string Routers(int n) => n == 1 ? "router" : n % 10 is >= 2 and <= 4 && n % 100 is not (>= 12 and <= 14) ? "routery" : "routerów";

    /// <summary>Hosts worth a traceroute: no layer-2 evidence, and either a lowered TTL or no TTL at all.</summary>
    public static bool NeedsTrace(LinkFacts f) =>
        !f.IsLocalMachine && !(f.ViaArp && f.Mac is not null) && (HopsFromTtl(f.Ttl) is null or > 0)
        && IPAddress.TryParse(f.Ip, out var ip) && !IPAddress.IsLoopback(ip);
}
