using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Weles.Infrastructure.Scanning;

public sealed record CertificateSnapshot(
    string Subject,
    string Issuer,
    DateTime NotBefore,
    DateTime NotAfter,
    string Thumbprint,
    string? SerialNumber,
    IReadOnlyList<string> SubjectAlternativeNames,
    string? KeyAlgorithm,
    int? KeySize,
    string? SignatureAlgorithm,
    string? TlsProtocol,
    string? CipherSuite,
    bool IsSelfSigned,
    bool? HostnameMatches,
    SslPolicyErrors ValidationErrors)
{
    public static CertificateSnapshot From(X509Certificate2 cert, string? hostname, string? protocol, string? cipher, SslPolicyErrors errors)
    {
        var sans = new List<string>();
        foreach (var ext in cert.Extensions.OfType<X509SubjectAlternativeNameExtension>())
        {
            sans.AddRange(ext.EnumerateDnsNames());
            sans.AddRange(ext.EnumerateIPAddresses().Select(a => a.ToString()));
        }

        int? keySize = null;
        using (var rsa = cert.GetRSAPublicKey()) keySize ??= rsa?.KeySize;
        using (var ec = cert.GetECDsaPublicKey()) keySize ??= ec?.KeySize;

        bool? matches = null;
        if (!string.IsNullOrWhiteSpace(hostname))
        {
            try
            {
                matches = cert.MatchesHostname(hostname);
            }
            catch (ArgumentException)
            {
                matches = null;
            }
        }

        return new CertificateSnapshot(
            cert.Subject,
            cert.Issuer,
            cert.NotBefore.ToUniversalTime(),
            cert.NotAfter.ToUniversalTime(),
            cert.GetCertHashString(HashAlgorithmName.SHA256),
            cert.SerialNumber,
            sans,
            cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value,
            keySize,
            cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value,
            protocol,
            cipher,
            string.Equals(cert.Subject, cert.Issuer, StringComparison.Ordinal),
            matches,
            errors);
    }
}
