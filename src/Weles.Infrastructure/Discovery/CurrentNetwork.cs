using System.Net;
using Weles.Core.Networking;

namespace Weles.Infrastructure.Discovery;

/// <summary>A network this machine is attached to right now: interface CIDR and its gateway's MAC (if in the ARP cache).</summary>
public sealed record AttachedNetwork(string Cidr, string? GatewayMac);

public interface ICurrentNetworkProvider
{
    IReadOnlyList<AttachedNetwork> GetAttachedNetworks();
}

/// <summary>Reads only local state (interfaces, ARP cache) – opening the inventory never sends traffic to the network.</summary>
public sealed class CurrentNetworkProvider(LocalNetworkDiscovery localNetwork) : ICurrentNetworkProvider
{
    public IReadOnlyList<AttachedNetwork> GetAttachedNetworks()
    {
        var arp = ArpTable.Read();
        return localNetwork.GetInterfaces()
            .Select(i => new AttachedNetwork(i.NetworkCidr,
                i.Gateway is not null && IPAddress.TryParse(i.Gateway, out var gw) ? NetworkIdentity.Fingerprint([arp.GetValueOrDefault(gw)]) : null))
            .Distinct()
            .ToList();
    }
}
