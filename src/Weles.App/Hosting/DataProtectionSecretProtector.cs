using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Weles.Infrastructure.Integrations;

namespace Weles.App.Hosting;

/// <summary>Secrets (e.g. the DefectDojo API key) encrypted with the application's Data Protection keys (keys directory, DPAPI on Windows).</summary>
public sealed class DataProtectionSecretProtector(IDataProtectionProvider provider) : ISecretProtector
{
    private readonly IDataProtector _protector = provider.CreateProtector("Weles.Secrets.v1");

    public string Protect(string plaintext) => _protector.Protect(plaintext);

    public string? Unprotect(string protectedText)
    {
        try
        {
            return _protector.Unprotect(protectedText);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}
