using System.IO.Compression;
using System.Text;

namespace Weles.Infrastructure.Discovery;

/// <summary>
/// Vendor lookup by MAC prefix using the bundled IEEE MA-L registry oui.txt (refresh with deploy/tools/update-oui.sh).
/// Loaded lazily on first use; works offline.
/// </summary>
public sealed class OuiDatabase
{
    private readonly Lazy<Dictionary<uint, string>> _entries;

    public OuiDatabase() : this(() => typeof(OuiDatabase).Assembly.GetManifestResourceStream("Weles.oui.txt.gz")
                                      ?? throw new InvalidOperationException("Embedded OUI registry is missing."))
    {
    }

    public OuiDatabase(Func<Stream> gzipRegistrySource)
    {
        _entries = new Lazy<Dictionary<uint, string>>(() =>
        {
            using var gz = new GZipStream(gzipRegistrySource(), CompressionMode.Decompress);
            using var reader = new StreamReader(gz, Encoding.UTF8);
            return Parse(reader);
        });
    }

    public int Count => _entries.Value.Count;

    public string? Lookup(string? mac)
    {
        if (!TryParseMac(mac, out var bytes))
        {
            return null;
        }

        var prefix = (uint)(bytes[0] << 16 | bytes[1] << 8 | bytes[2]);
        if (WellKnownVirtualPrefixes.TryGetValue(prefix, out var virtualVendor))
        {
            return virtualVendor;
        }

        if (_entries.Value.TryGetValue(prefix, out var vendor))
        {
            return vendor;
        }

        return IsLocallyAdministered(bytes) ? "Adres losowy / administrowany lokalnie" : null;
    }

    /// <summary>Locally administered addresses (e.g. phone MAC randomization) have no registered vendor.</summary>
    public static bool IsLocallyAdministered(byte[] mac) => (mac[0] & 0x02) != 0;

    /// <summary>Normalizes "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff", "AA:BB:..." to "aa:bb:cc:dd:ee:ff".</summary>
    public static string? Normalize(string? mac) =>
        TryParseMac(mac, out var b) ? string.Join(':', b.Select(x => x.ToString("x2"))) : null;

    public static bool TryParseMac(string? mac, out byte[] bytes)
    {
        bytes = [];
        if (string.IsNullOrWhiteSpace(mac)) return false;
        var hex = new string(mac.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length != 12) return false;
        bytes = Convert.FromHexString(hex);
        return bytes.Any(b => b != 0) && bytes.Any(b => b != 0xFF);
    }

    /// <summary>Parses the IEEE oui.txt registry: lines of the form "00-22-61   (hex)\t\tFrontier Silicon Ltd".</summary>
    internal static Dictionary<uint, string> Parse(TextReader reader)
    {
        var result = new Dictionary<uint, string>(40_000);
        while (reader.ReadLine() is { } line)
        {
            var marker = line.IndexOf("(hex)", StringComparison.Ordinal);
            if (marker < 8) continue;
            var hex = line[..marker].Trim().Replace("-", "");
            var name = line[(marker + 5)..].Trim();
            if (hex.Length == 6 && name.Length > 0 && uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var prefix))
            {
                result.TryAdd(prefix, name);
            }
        }

        return result;
    }

    /// <summary>Virtualization prefixes that are not (or not clearly) in the IEEE registry.</summary>
    private static readonly Dictionary<uint, string> WellKnownVirtualPrefixes = new()
    {
        [0x525400] = "QEMU/KVM (virtio)",
        [0x00155D] = "Microsoft Hyper-V",
        [0x080027] = "Oracle VirtualBox",
        [0x000C29] = "VMware",
        [0x005056] = "VMware",
        [0x001C42] = "Parallels",
    };
}
