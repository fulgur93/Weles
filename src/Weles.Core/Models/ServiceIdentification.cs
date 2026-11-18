namespace Weles.Core.Models;

/// <summary>Result of identifying the software behind an open port.</summary>
public sealed record ServiceIdentification
{
    public required string ServiceName { get; init; }
    public string? Product { get; init; }
    public string? Vendor { get; init; }
    public string? Version { get; init; }
    public string? Cpe { get; init; }

    /// <summary>Raw banner or the most relevant response line, sanitized.</summary>
    public string? Banner { get; init; }

    /// <summary>Distribution hint from the banner (e.g. "Ubuntu") – the vendor may backport fixes without changing the version.</summary>
    public string? DistributionHint { get; init; }

    public string? OsHint { get; init; }

    /// <summary>0–100. Port-number-only guesses never exceed 25 and never carry a product or version.</summary>
    public int Confidence { get; init; }

    public required string Method { get; init; }
    public bool IsTls { get; init; }
    public Dictionary<string, string> Extra { get; init; } = [];

    public static ServiceIdentification FromPortOnly(int port) => new()
    {
        ServiceName = Networking.WellKnownPorts.NameOf(port) ?? "unknown",
        Confidence = Networking.WellKnownPorts.NameOf(port) is null ? 5 : 20,
        Method = "port-hint"
    };
}
