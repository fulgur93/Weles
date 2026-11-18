namespace Weles.Core.Entities;

public class NetworkSegment
{
    public int Id { get; set; }
    public required string Cidr { get; set; }
    public string? Name { get; set; }
    public string? Gateway { get; set; }
    public DateTime FirstSeenAt { get; set; }
    public DateTime LastSeenAt { get; set; }

    public List<Asset> Assets { get; set; } = [];
}
