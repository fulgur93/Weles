using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace Weles.Core.Networking;

/// <summary>Inclusive IPv4 range stored as host-order integers.</summary>
public readonly record struct Ipv4Range(uint Start, uint End)
{
    public long Count => (long)End - Start + 1;

    public bool Contains(uint value) => value >= Start && value <= End;

    public IEnumerable<IPAddress> Enumerate()
    {
        for (long i = Start; i <= End; i++)
        {
            yield return Ipv4.FromUInt((uint)i);
        }
    }

    public override string ToString() => Start == End ? Ipv4.FromUInt(Start).ToString() : $"{Ipv4.FromUInt(Start)}-{Ipv4.FromUInt(End)}";
}

public static class Ipv4
{
    public static uint ToUInt(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("IPv4 address expected", nameof(address));
        }

        var b = address.GetAddressBytes();
        return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
    }

    public static IPAddress FromUInt(uint value) =>
        new([(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value]);

    public static uint MaskFromPrefix(int prefix) => prefix <= 0 ? 0 : uint.MaxValue << (32 - prefix);

    public static int PrefixFromMask(IPAddress mask) => BitOperations.PopCount(ToUInt(mask));

    /// <param name="hostsOnly">Skip network and broadcast addresses for prefixes up to /30.</param>
    public static Ipv4Range CidrRange(uint address, int prefix, bool hostsOnly)
    {
        var mask = MaskFromPrefix(prefix);
        var network = address & mask;
        var broadcast = network | ~mask;
        return hostsOnly && prefix <= 30 ? new Ipv4Range(network + 1, broadcast - 1) : new Ipv4Range(network, broadcast);
    }

    public static string CidrNotation(uint address, int prefix) => $"{FromUInt(address & MaskFromPrefix(prefix))}/{prefix}";
}
