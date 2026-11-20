namespace Weles.Infrastructure.External;

public sealed class ExternalOptions
{
    public const string SectionName = "Weles:External";

    /// <summary>DNS servers to ask (IP or IP:port). Empty – the resolvers configured in the operating system.</summary>
    public string[] DnsServers { get; set; } = [];

    public int DnsTimeoutMs { get; set; } = 2500;

    /// <summary>Upper bound on host names resolved in one analysis (CT logs of large domains list thousands).</summary>
    public int MaxHosts { get; set; } = 300;

    public int DnsConcurrency { get; set; } = 8;

    public string CertificateTransparencyUrl { get; set; } = "https://crt.sh/";
    public int CertificateTransparencyTimeoutSeconds { get; set; } = 60;
    public long CertificateTransparencyMaxBytes { get; set; } = 32 * 1024 * 1024;
}
