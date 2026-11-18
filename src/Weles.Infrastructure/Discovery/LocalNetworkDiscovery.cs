using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Weles.Core.Networking;

namespace Weles.Infrastructure.Discovery;

public sealed record LocalInterfaceInfo(
    string Name,
    string Description,
    string Type,
    string? MacAddress,
    string? Vendor,
    string Address,
    int PrefixLength,
    string NetworkCidr,
    string? Gateway,
    long HostCount,
    string SuggestedScope,
    string? Note);

/// <summary>Detects the machine's own network segments to suggest scan scopes.</summary>
public sealed class LocalNetworkDiscovery(OuiDatabase oui)
{
    /// <summary>Networks larger than this are suggested as the /24 around the local address.</summary>
    public const int LargestSuggestedPrefix = 22;

    public IReadOnlyList<LocalInterfaceInfo> GetInterfaces()
    {
        var result = new List<LocalInterfaceInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            IPInterfaceProperties props;
            try
            {
                props = nic.GetIPProperties();
            }
            catch (NetworkInformationException)
            {
                continue;
            }

            var gateway = props.GatewayAddresses.Select(g => g.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
            var macBytes = nic.GetPhysicalAddress().GetAddressBytes();
            var mac = macBytes.Length == 6 ? OuiDatabase.Normalize(Convert.ToHexString(macBytes)) : null;

            foreach (var unicast in props.UnicastAddresses.Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork))
            {
                var classification = AddressClassifier.Classify(unicast.Address);
                if (classification is AddressScope.Loopback or AddressScope.LinkLocal) continue;

                var prefix = unicast.PrefixLength is > 0 and <= 32 ? unicast.PrefixLength : 24;
                var addr = Ipv4.ToUInt(unicast.Address);
                var network = Ipv4.CidrNotation(addr, prefix);
                var hosts = Ipv4.CidrRange(addr, prefix, hostsOnly: true).Count;
                string suggested = network;
                string? note = null;
                if (prefix < LargestSuggestedPrefix)
                {
                    suggested = Ipv4.CidrNotation(addr, 24);
                    note = $"Sieć {network} ma {hosts} adresów – proponowany zakres zawężono do /24 wokół adresu tego komputera.";
                }

                if (classification == AddressScope.Public)
                {
                    note = "Interfejs ma adres publiczny – skanowanie wymaga osobnego zezwolenia na adresy publiczne.";
                }

                result.Add(new LocalInterfaceInfo(nic.Name, nic.Description, InterfaceType(nic), mac,
                    oui.Lookup(mac), unicast.Address.ToString(), prefix, network, gateway?.ToString(), hosts, suggested, note));
            }
        }

        return result;
    }

    /// <summary>.NET reports Wi‑Fi adapters as Ethernet on Linux; the kernel exposes the truth in sysfs.</summary>
    private static string InterfaceType(NetworkInterface nic) =>
        OperatingSystem.IsLinux() && Directory.Exists($"/sys/class/net/{nic.Name}/wireless") ? "Wi‑Fi"
        : nic.NetworkInterfaceType switch
        {
            NetworkInterfaceType.Wireless80211 => "Wi‑Fi",
            NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or NetworkInterfaceType.FastEthernetT => "Ethernet",
            var other => other.ToString()
        };

    public IReadOnlySet<IPAddress> GetGateways() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .SelectMany(n =>
            {
                try { return n.GetIPProperties().GatewayAddresses.Select(g => g.Address); }
                catch (NetworkInformationException) { return []; }
            })
            .Where(a => !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any))
            .ToHashSet();
}
