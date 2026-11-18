using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Weles.Infrastructure.Discovery;

/// <summary>
/// Reads the operating system's neighbour (ARP) cache. No raw sockets or administrator rights are needed:
/// a TCP/ICMP probe makes the kernel resolve the MAC address, and WELES just reads the result.
/// </summary>
public static class ArpTable
{
    public static IReadOnlyDictionary<IPAddress, string> Read()
    {
        try
        {
            if (OperatingSystem.IsLinux() && File.Exists("/proc/net/arp"))
            {
                return ParseLinux(File.ReadAllText("/proc/net/arp"));
            }

            if (OperatingSystem.IsWindows())
            {
                return ReadWindows();
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ExternalException)
        {
            // ARP is an enrichment only – discovery continues without MAC addresses.
        }

        return new Dictionary<IPAddress, string>();
    }

    /// <summary>Parses /proc/net/arp. Flag 0x2 (ATF_COM) means the entry is complete.</summary>
    public static IReadOnlyDictionary<IPAddress, string> ParseLinux(string content)
    {
        var result = new Dictionary<IPAddress, string>();
        foreach (var line in content.Split('\n').Skip(1))
        {
            var cols = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length < 4 || !IPAddress.TryParse(cols[0], out var ip)) continue;
            if (!int.TryParse(cols[2].Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out var flags) || (flags & 0x2) == 0) continue;
            if (OuiDatabase.Normalize(cols[3]) is { } mac)
            {
                result[ip] = mac;
            }
        }

        return result;
    }

    [SupportedOSPlatform("windows")]
    private static Dictionary<IPAddress, string> ReadWindows()
    {
        var result = new Dictionary<IPAddress, string>();
        var size = 0;
        _ = GetIpNetTable(IntPtr.Zero, ref size, false);
        if (size <= 0) return result;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpNetTable(buffer, ref size, false) != 0) return result;
            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibIpNetRow>();
            var ptr = buffer + 4;
            for (var i = 0; i < count; i++, ptr += rowSize)
            {
                var row = Marshal.PtrToStructure<MibIpNetRow>(ptr);
                // 3 = dynamic, 4 = static; 2 = invalid
                if (row.PhysAddrLen != 6 || row.Type is not (3 or 4)) continue;
                var mac = new[] { row.Mac0, row.Mac1, row.Mac2, row.Mac3, row.Mac4, row.Mac5 };
                if (OuiDatabase.Normalize(Convert.ToHexString(mac)) is { } normalized)
                {
                    result[new IPAddress(BitConverter.GetBytes(row.Addr))] = normalized;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpNetRow
    {
        public int Index;
        public int PhysAddrLen;
        public byte Mac0, Mac1, Mac2, Mac3, Mac4, Mac5, Mac6, Mac7;
        public uint Addr;
        public int Type;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [SupportedOSPlatform("windows")]
    private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);
}
