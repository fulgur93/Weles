namespace Weles.Core.Rules;

public static class NetworkNaming
{
    /// <summary>
    /// "192.168.0.0/24 · TP-LINK c0:4a:00:ee:19:4a" – the gateway MAC is part of the label because two networks often
    /// have the same range and a router from the same vendor.
    /// </summary>
    public static string Label(string cidr, string? name, string? gatewayVendor, string? gatewayMac)
    {
        if (!string.IsNullOrWhiteSpace(name)) return name.Trim();
        if (gatewayMac is null) return cidr;
        var vendor = AssetNaming.ShortVendor(gatewayVendor);
        var mac = gatewayMac.Split(',')[0];
        return vendor is null || vendor == AssetNaming.RandomMacVendor ? $"{cidr} · router {mac}" : $"{cidr} · {vendor} {mac}";
    }
}
