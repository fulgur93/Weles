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

                // A VPN subnet is shared with other people's computers (other users of the same VPN): never suggest
                // scanning it as a whole – only single addresses the user is allowed to test.
                if (IsVpn(nic))
                {
                    suggested = "";
                    note = "Interfejs VPN – w tej sieci są też komputery innych osób. Nie skanuj całej sieci; dodaj zakres z pojedynczym adresem maszyny, którą wolno Ci testować.";
                }

                result.Add(new LocalInterfaceInfo(nic.Name, nic.Description, InterfaceType(nic), mac,
                    oui.Lookup(mac), unicast.Address.ToString(), prefix, network, gateway?.ToString(), hosts, suggested, note));
            }
        }

        return result;
    }

    /// <summary>
    /// VPN tunnels: .NET reports Linux tun/wg devices as "Unknown", so the kernel is asked as well (ARPHRD_NONE = 65534,
    /// ARPHRD_PPP = 512, or a tun_flags file for tun/tap), with common names as a fallback.
    /// </summary>
    internal static bool IsVpn(NetworkInterface nic)
    {
        if (nic.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp) return true;
        if (OperatingSystem.IsLinux())
        {
            try
            {
                var path = $"/sys/class/net/{nic.Name}";
                if (File.Exists($"{path}/tun_flags")) return true;
                if (File.Exists($"{path}/type") && File.ReadAllText($"{path}/type").Trim() is "65534" or "512" or "776") return true;
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        return IsVpnName(nic.Name) || IsVpnName(nic.Description);
    }

    internal static bool IsVpnName(string? name) =>
        name is not null && (System.Text.RegularExpressions.Regex.IsMatch(name, @"^(tun|tap|wg|ppp|utun|ipsec|nordlynx|tailscale|zt)\d*", System.Text.RegularExpressions.RegexOptions.IgnoreCase)
            || name.Contains("VPN", StringComparison.OrdinalIgnoreCase) || name.Contains("WireGuard", StringComparison.OrdinalIgnoreCase)
            || name.Contains("TAP-Windows", StringComparison.OrdinalIgnoreCase) || name.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase));

    /// <summary>.NET reports Wi‑Fi adapters as Ethernet on Linux; the kernel exposes the truth in sysfs.</summary>
    private static string InterfaceType(NetworkInterface nic) =>
        IsVpn(nic) ? "VPN"
        : OperatingSystem.IsLinux() && Directory.Exists($"/sys/class/net/{nic.Name}/wireless") ? "Wi‑Fi"
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

    /// <summary>MAC addresses of every physical interface of this machine, also those currently down (Wi‑Fi vs cable).</summary>
    public IReadOnlySet<string> GetLocalMacAddresses() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
            .Select(n => n.GetPhysicalAddress().GetAddressBytes())
            .Where(b => b.Length == 6 && b.Any(x => x != 0))
            .Select(b => OuiDatabase.Normalize(Convert.ToHexString(b)))
            .OfType<string>()
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
}
