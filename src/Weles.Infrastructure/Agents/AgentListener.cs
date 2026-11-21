using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Weles.Core.Networking;
using Weles.Infrastructure.Platform;

namespace Weles.Infrastructure.Agents;

/// <summary>
/// The HTTPS endpoint agents connect to. Off by default; when on, it listens on one chosen private address of this
/// computer (never "all interfaces", never a public address) and serves the agent protocol only – the panel stays on
/// 127.0.0.1. Stored in config/agent-listener.json and applied when WELES starts.
/// </summary>
public sealed record AgentListenerSettings(bool Enabled = false, string Address = "127.0.0.1", int Port = AgentListenerSettings.DefaultPort)
{
    public const int DefaultPort = 7443;
    public const string FileName = "agent-listener.json";

    /// <summary>Null when the settings can be used; otherwise the reason.</summary>
    public string? Validate()
    {
        if (Port is < 1024 or > 65535) return "Port musi być z zakresu 1024–65535.";
        if (!IPAddress.TryParse(Address, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return "Podaj adres IPv4 tego komputera.";
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.Broadcast)) return "Wybierz konkretny adres – nasłuch na wszystkich interfejsach nie jest dozwolony.";
        if (AddressClassifier.IsPublic(ip)) return "Adres publiczny jest niedozwolony – agenci łączą się przez sieć lokalną lub VPN.";
        return null;
    }

    public static AgentListenerSettings Load(WelesPaths paths)
    {
        var file = Path.Combine(paths.ConfigDirectory, FileName);
        try
        {
            return File.Exists(file) ? JsonSerializer.Deserialize<AgentListenerSettings>(File.ReadAllText(file)) ?? new() : new();
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            return new AgentListenerSettings();
        }
    }

    public void Save(WelesPaths paths)
    {
        Directory.CreateDirectory(paths.ConfigDirectory);
        File.WriteAllText(Path.Combine(paths.ConfigDirectory, FileName), JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }
}

/// <summary>What WELES applied at startup – the UI shows it next to the saved settings (which need a restart).</summary>
/// <param name="Error">Why the listener is not running although it is enabled (e.g. the port is taken).</param>
public sealed record AgentListenerState(AgentListenerSettings Active, string? Pin, string? Error)
{
    public bool IsListening => Active.Enabled && Error is null;

    public string Url => $"https://{Active.Address}:{Active.Port}";
}

/// <summary>
/// The endpoint's own certificate: self-signed ECDSA P-256, created once in the keys directory (0700). Agents do not
/// trust it through a CA – they pin its SHA-256, given at enrollment. It is never replaced automatically, since that
/// would cut off every enrolled agent.
/// </summary>
public static class AgentCertificate
{
    public const string FileName = "agent-endpoint.pfx";

    public static X509Certificate2 LoadOrCreate(WelesPaths paths, string address)
    {
        var file = Path.Combine(paths.KeysDirectory, FileName);
        if (!File.Exists(file))
        {
            Directory.CreateDirectory(paths.KeysDirectory);
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=WELES agent endpoint, O=WELES", key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(Environment.MachineName);
            san.AddIpAddress(IPAddress.Loopback);
            if (IPAddress.TryParse(address, out var ip) && !ip.Equals(IPAddress.Loopback)) san.AddIpAddress(ip);
            request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
            var now = DateTimeOffset.UtcNow;
            using var created = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(10));
            File.WriteAllBytes(file, created.Export(X509ContentType.Pfx));
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        return X509CertificateLoader.LoadPkcs12FromFile(file, null);
    }
}
