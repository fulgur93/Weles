using System.Net;
using System.Net.Sockets;

namespace Weles.Core.Networking;

public enum AddressScope
{
    Loopback,
    Private,
    LinkLocal,
    SharedAddressSpace,
    Public,
    Reserved
}

public static class AddressClassifier
{
    public static AddressScope Classify(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var v = Ipv4.ToUInt(address);
            if (In(v, "127.0.0.0", 8)) return AddressScope.Loopback;
            if (In(v, "10.0.0.0", 8) || In(v, "172.16.0.0", 12) || In(v, "192.168.0.0", 16)) return AddressScope.Private;
            if (In(v, "169.254.0.0", 16)) return AddressScope.LinkLocal;
            if (In(v, "100.64.0.0", 10)) return AddressScope.SharedAddressSpace;
            if (In(v, "0.0.0.0", 8) || In(v, "224.0.0.0", 4) || In(v, "240.0.0.0", 4)
                || In(v, "192.0.2.0", 24) || In(v, "198.51.100.0", 24) || In(v, "203.0.113.0", 24) || In(v, "198.18.0.0", 15))
            {
                return AddressScope.Reserved;
            }

            return AddressScope.Public;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (IPAddress.IsLoopback(address)) return AddressScope.Loopback;
            if (address.IsIPv6LinkLocal) return AddressScope.LinkLocal;
            if (address.IsIPv6UniqueLocal || address.IsIPv6SiteLocal) return AddressScope.Private;
            if (address.IsIPv6Multicast || address.Equals(IPAddress.IPv6Any)) return AddressScope.Reserved;
            return AddressScope.Public;
        }

        return AddressScope.Reserved;
    }

    /// <summary>Public addresses may only be scanned when the scope explicitly allows them.</summary>
    public static bool IsPublic(IPAddress address) => Classify(address) == AddressScope.Public;

    private static bool In(uint value, string network, int prefix)
    {
        var mask = Ipv4.MaskFromPrefix(prefix);
        return (value & mask) == (Ipv4.ToUInt(IPAddress.Parse(network)) & mask);
    }
}
