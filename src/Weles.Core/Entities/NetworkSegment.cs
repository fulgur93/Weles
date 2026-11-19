namespace Weles.Core.Entities;

public class NetworkSegment
{
    public int Id { get; set; }
    public required string Cidr { get; set; }
    public string? Name { get; set; }
    /// <summary>Gateway IP address.</summary>
    public string? Gateway { get; set; }

    /// <summary>
    /// Gateway MAC (<see cref="Networking.NetworkIdentity"/>): a segment is a CIDR <em>on a specific network</em> – the
    /// same 192.168.0.0/24 at home and in the office are two segments. Null when the gateway was not seen.
    /// </summary>
    public string? GatewayMac { get; set; }

    public string? GatewayVendor { get; set; }
    public DateTime FirstSeenAt { get; set; }
    public DateTime LastSeenAt { get; set; }

    public List<Asset> Assets { get; set; } = [];
}
