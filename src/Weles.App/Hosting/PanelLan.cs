using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Weles.Core.Networking;
using Weles.Infrastructure.Platform;

namespace Weles.App.Hosting;

/// <summary>
/// Optional access to the panel from the local network. Off by default. When on, WELES listens with HTTPS on one chosen
/// private address of this computer (never all interfaces, never a public address), accepts only clients from that
/// address's own subnet, and every request needs a WELES account – the one-time launch token of the local browser is
/// not accepted there, and the first-administrator setup is possible only on 127.0.0.1. Stored in config/panel-lan.json,
/// applied when WELES starts.
/// </summary>
public sealed record PanelLanSettings(bool Enabled = false, string Address = "", int Port = PanelLanSettings.DefaultPort)
{
    public const int DefaultPort = 5443;
    public const string FileName = "panel-lan.json";
    public const string CertificateFile = "panel-lan.pfx";

    public string? Validate(int agentPort)
    {
        if (Port is < 1024 or > 65535) return "Port musi być z zakresu 1024–65535.";
        if (Port == agentPort) return "Ten port jest używany przez punkt dostępowy agentów – wybierz inny.";
        if (!IPAddress.TryParse(Address, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) return "Wybierz adres IPv4 tego komputera w sieci lokalnej.";
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.Broadcast) || IPAddress.IsLoopback(ip)) return "Wybierz konkretny adres w sieci lokalnej – nie 0.0.0.0 ani 127.0.0.1.";
        if (AddressClassifier.IsPublic(ip)) return "Adres publiczny jest niedozwolony – panel można udostępnić tylko w sieci prywatnej.";
        return null;
    }

    public static PanelLanSettings Load(WelesPaths paths)
    {
        var file = Path.Combine(paths.ConfigDirectory, FileName);
        try
        {
            return File.Exists(file) ? JsonSerializer.Deserialize<PanelLanSettings>(File.ReadAllText(file)) ?? new() : new();
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            return new PanelLanSettings();
        }
    }

    public void Save(WelesPaths paths)
    {
        Directory.CreateDirectory(paths.ConfigDirectory);
        File.WriteAllText(Path.Combine(paths.ConfigDirectory, FileName), JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }
}

/// <summary>What was applied at startup.</summary>
/// <param name="Subnet">The listening address's subnet (CIDR) – the only clients accepted.</param>
/// <param name="CertificateSha256">Fingerprint the user compares with the browser's warning for the self-signed certificate.</param>
public sealed record PanelLanState(PanelLanSettings Active, string? Error, string? Subnet, string? CertificateSha256)
{
    public bool IsListening => Active.Enabled && Error is null;
    public string Url => $"https://{Active.Address}:{Active.Port}";

    /// <summary>The request came in on the LAN listener (not on 127.0.0.1).</summary>
    public bool IsLanRequest(HttpContext context) => IsListening && context.Connection.LocalPort == Active.Port && context.Connection.LocalIpAddress is { } local && !IPAddress.IsLoopback(local);

    public bool AllowsClient(IPAddress? remote)
    {
        if (remote is null || Subnet is null) return false;
        if (remote.IsIPv4MappedToIPv6) remote = remote.MapToIPv4();
        if (remote.AddressFamily != AddressFamily.InterNetwork) return false;
        var parts = Subnet.Split('/');
        var range = Ipv4.CidrRange(Ipv4.ToUInt(IPAddress.Parse(parts[0])), int.Parse(parts[1]), hostsOnly: false);
        return range.Contains(Ipv4.ToUInt(remote));
    }

    public bool IsExpectedHost(HostString host) =>
        string.Equals(host.Host, Active.Address, StringComparison.Ordinal) && (host.Port is null || host.Port == Active.Port);

    /// <summary>The network (CIDR) of a local interface address; null when no interface has it.</summary>
    public static string? SubnetOf(string address)
    {
        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
            foreach (var u in nic.GetIPProperties().UnicastAddresses)
            {
                if (u.Address.AddressFamily != AddressFamily.InterNetwork || u.Address.ToString() != address) continue;
                return Ipv4.CidrNotation(Ipv4.ToUInt(u.Address), u.PrefixLength);
            }
        }

        return null;
    }

    public static PanelLanState Configure(WebApplicationBuilder builder, WelesPaths paths, int agentPort)
    {
        var settings = PanelLanSettings.Load(paths);
        if (!settings.Enabled) return new PanelLanState(settings, null, null, null);
        if (settings.Validate(agentPort) is { } invalid) return new PanelLanState(settings, invalid, null, null);

        var subnet = SubnetOf(settings.Address);
        if (subnet is null) return new PanelLanState(settings, $"Adres {settings.Address} nie należy już do tego komputera (inna sieć?) – panel działa tylko na 127.0.0.1.", null, null);

        var address = IPAddress.Parse(settings.Address);
        try
        {
            using var probe = new TcpListener(address, settings.Port);
            probe.Start();
            probe.Stop();
        }
        catch (SocketException ex)
        {
            return new PanelLanState(settings, ex.SocketErrorCode == SocketError.AddressAlreadyInUse ? $"Port {settings.Port} jest zajęty przez inny program." : ex.Message, null, null);
        }

        var certificate = Weles.Infrastructure.Agents.AgentCertificate.LoadOrCreate(paths, settings.Address, PanelLanSettings.CertificateFile, "CN=WELES panel, O=WELES");
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(address, settings.Port, listen => listen.UseHttps(certificate, https =>
            https.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13)));
        var fingerprint = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(certificate.RawData));
        return new PanelLanState(settings, null, subnet, string.Join(':', Enumerable.Range(0, fingerprint.Length / 2).Select(i => fingerprint.Substring(i * 2, 2))));
    }
}
