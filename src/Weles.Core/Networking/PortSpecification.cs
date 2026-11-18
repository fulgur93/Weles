using System.Diagnostics.CodeAnalysis;

namespace Weles.Core.Networking;

public static class PortSpecification
{
    public const string Quick = "quick";
    public const string Standard = "standard";
    public const string Mobile = "mobile";

    /// <summary>
    /// Services that phones and tablets expose when a debugging or sharing feature is left on:
    /// ADB over TCP (5555), file-sharing FTP servers (2121, 2221 – e.g. Xiaomi ShareMe/Mi File Manager), Termux SSH (8022),
    /// AirDroid (8888/8889), KDE Connect (1714–1764), iPhone sync (62078), AirPlay (7000).
    /// Android "wireless debugging" uses a random port – it is found through mDNS, not through this list.
    /// </summary>
    public static readonly IReadOnlyList<int> MobileOnlyPorts =
    [
        5555, 5037, 2121, 2221, 8022, 2222, 8888, 8889, 7000, 62078, 8080, 8000, 9090, 1234, 12345, .. Enumerable.Range(1714, 51)
    ];

    /// <summary>The ports named in the product requirements plus common IoT/admin ports.</summary>
    public static readonly IReadOnlyList<int> QuickPorts =
    [
        20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 554, 587, 631, 993, 995,
        1433, 1883, 2049, 2375, 3306, 3389, 5000, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 8888, 9100, 9200, 27017
    ];

    /// <summary>Roughly the 120 most common TCP services seen in enterprise and home networks.</summary>
    public static readonly IReadOnlyList<int> StandardPorts =
    [
        .. QuickPorts,
        7, 9, 13, 37, 79, 81, 88, 106, 113, 119, 137, 161, 179, 199, 427, 444, 464, 497, 513, 514, 515, 543, 544, 548,
        593, 636, 646, 873, 902, 990, 1025, 1026, 1027, 1080, 1194, 1521, 1720, 1723, 1900, 2000, 2001, 2082, 2083, 2181,
        2222, 2376, 3000, 3128, 3268, 3690, 4443, 4444, 4567, 5001, 5060, 5061, 5353, 5601, 5672, 5800, 5901, 5986,
        6000, 6443, 6667, 7001, 7070, 7443, 7547, 8008, 8009, 8081, 8086, 8088, 8181, 8291, 8333, 8530, 8834, 9000,
        9001, 9090, 9091, 9443, 9999, 10000, 10250, 11211, 15672, 32400, 49152, 50000
    ];

    public const int MaximumPorts = 65_535;

    public static bool TryParse(string? specification, [NotNullWhen(true)] out IReadOnlyList<int>? ports, out string? error)
    {
        ports = null;
        error = null;
        var spec = (specification ?? "").Trim().ToLowerInvariant();

        switch (spec)
        {
            case Quick:
                ports = Sorted(QuickPorts);
                return true;
            case Standard:
                ports = Sorted(StandardPorts);
                return true;
            case Mobile:
                ports = Sorted([.. QuickPorts, .. MobileOnlyPorts]);
                return true;
            case "":
                error = "Nie podano portów.";
                return false;
        }

        var set = new SortedSet<int>();
        foreach (var token in spec.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (token is Quick or Standard or Mobile)
            {
                set.UnionWith(token switch { Quick => QuickPorts, Standard => StandardPorts, _ => [.. QuickPorts, .. MobileOnlyPorts] });
                continue;
            }

            var range = token.Split('-', 2);
            var to = 0;
            if (!int.TryParse(range[0], out var from) || (range.Length == 2 && !int.TryParse(range[1], out to)))
            {
                error = $"Nieprawidłowy port lub zakres: {token}";
                return false;
            }

            if (range.Length == 1)
            {
                to = from;
            }

            if (from is < 1 or > 65535 || to is < 1 or > 65535 || to < from)
            {
                error = $"Port musi mieścić się w zakresie 1–65535: {token}";
                return false;
            }

            for (var p = from; p <= to; p++)
            {
                set.Add(p);
            }
        }

        if (set.Count == 0)
        {
            error = "Nie podano portów.";
            return false;
        }

        ports = [.. set];
        return true;
    }

    private static int[] Sorted(IEnumerable<int> ports) => [.. ports.Distinct().Order()];
}
