using System.Net;
using Weles.Core.Topology;
using Weles.Infrastructure.Scanning;

namespace Weles.Tests.Topology;

/// <summary>Topology links rest on observations from the scan (ARP, TTL, traceroute) or are marked as inferred.</summary>
public class LinkEvidenceTests
{
    [Theory]
    [InlineData(64, 0)]
    [InlineData(63, 1)]
    [InlineData(128, 0)]
    [InlineData(126, 2)]
    [InlineData(255, 0)]
    [InlineData(250, 5)]
    [InlineData(100, 28)]   // 128 − 100: unusual, but still "routed"
    public void Hops_are_estimated_from_the_reply_ttl(int ttl, int hops) => Assert.Equal(hops, TopologyEvidence.HopsFromTtl(ttl));

    [Fact]
    public void The_strongest_observation_decides_and_inference_is_named_as_such()
    {
        var arp = TopologyEvidence.For(new LinkFacts("192.168.0.20", true, "aa:bb:cc:00:00:20", 64, null));
        Assert.Equal((LinkKind.ArpNeighbour, 0, true), (arp.Kind, arp.Hops, arp.Observed));
        Assert.Contains("tablicy ARP", arp.Reason);

        var direct = TopologyEvidence.For(new LinkFacts("192.168.0.21", false, null, 128, null));
        Assert.Equal((LinkKind.TtlDirect, 0), (direct.Kind, direct.Hops));

        var routed = TopologyEvidence.For(new LinkFacts("10.20.0.5", false, null, 61, null));
        Assert.Equal((LinkKind.TtlRouted, 3, true), (routed.Kind, routed.Hops, routed.Routed));
        Assert.Contains("3 routery", routed.Reason);
        Assert.Contains("5 routerów", TopologyEvidence.For(new LinkFacts("10.20.0.5", false, null, 59, null)).Reason);

        // A lowered TTL beats a cached ARP entry (e.g. proxy ARP) – the packet itself crossed routers.
        Assert.Equal(LinkKind.TtlRouted, TopologyEvidence.For(new LinkFacts("10.20.0.6", true, "aa:bb:cc:00:00:06", 62, null)).Kind);

        var traced = TopologyEvidence.For(new LinkFacts("10.20.0.5", false, null, 62, ["192.168.0.1", "10.0.0.1", "10.20.0.5"]));
        Assert.Equal((LinkKind.Traceroute, 2), (traced.Kind, traced.Hops));
        Assert.Equal(["192.168.0.1", "10.0.0.1"], traced.Path);
        Assert.Contains("192.168.0.1 → 10.0.0.1", traced.Reason);

        var partial = TopologyEvidence.For(new LinkFacts("10.20.0.9", false, null, null, ["192.168.0.1"]));
        Assert.Equal((LinkKind.Traceroute, null), (partial.Kind, partial.Hops));
        Assert.Contains("nie odpowiedział", partial.Reason);

        var inferred = TopologyEvidence.For(new LinkFacts("192.168.0.30", false, null, null, null));
        Assert.Equal((LinkKind.Inferred, false), (inferred.Kind, inferred.Observed));
        Assert.Contains("wywnioskowane", inferred.Reason);
    }

    [Fact]
    public void Traceroute_runs_only_where_layer_two_gives_no_answer()
    {
        Assert.False(TopologyEvidence.NeedsTrace(new LinkFacts("192.168.0.20", true, "aa:bb:cc:00:00:20", 64, null)));  // ARP neighbour
        Assert.False(TopologyEvidence.NeedsTrace(new LinkFacts("192.168.0.21", false, null, 64, null)));               // TTL unchanged
        Assert.True(TopologyEvidence.NeedsTrace(new LinkFacts("10.20.0.5", false, null, 61, null)));                   // routed
        Assert.True(TopologyEvidence.NeedsTrace(new LinkFacts("10.20.0.6", false, null, null, null)));                 // no evidence at all
        Assert.False(TopologyEvidence.NeedsTrace(new LinkFacts("127.0.0.1", false, null, null, null)));
    }

    [Fact]
    public void Tracepath_output_is_parsed_into_the_router_path()
    {
        const string output = """
             1?: [LOCALHOST]                      pmtu 1500
             1:  192.168.0.1                                           0.512ms
             1:  192.168.0.1                                           0.430ms
             2:  no reply
             3:  10.0.0.1                                              3.120ms asymm  4
             4:  10.20.0.5                                             3.551ms reached
                 Resume: pmtu 1500 hops 4 back 4
            """;
        Assert.Equal(["192.168.0.1", "10.0.0.1", "10.20.0.5"], TracerouteProbe.ParseTracepath(output, IPAddress.Parse("10.20.0.5")));
        Assert.Empty(TracerouteProbe.ParseTracepath(" 1:  no reply\n 2:  no reply\n", IPAddress.Parse("10.20.0.5")));

        // Real output of an unprivileged tracepath through a router (Docker lab: 10.231.1.0/24 → router → 10.231.2.0/24).
        const string lab = " 1?: [LOCALHOST]                      pmtu 1500\n 1:  10.231.1.254                                          0.102ms \n 1:  10.231.1.254                                          0.014ms \n 2:  10.231.2.10                                           0.041ms reached\n     Resume: pmtu 1500 hops 2 back 2 \n";
        var path = TracerouteProbe.ParseTracepath(lab, IPAddress.Parse("10.231.2.10"));
        Assert.Equal(["10.231.1.254", "10.231.2.10"], path);
        var evidence = TopologyEvidence.For(new LinkFacts("10.231.2.10", false, null, 63, path));
        Assert.Equal((LinkKind.Traceroute, 1), (evidence.Kind, evidence.Hops));
        Assert.Equal(["10.231.1.254"], evidence.Path);
        Assert.Empty(TracerouteProbe.ParseTracepath(" 1:  999.1.1.1  1ms\n", IPAddress.Parse("10.20.0.5")));
    }
}
