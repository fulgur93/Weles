using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Weles.App.Hosting;

/// <summary>
/// Random secret generated on every start. The browser receives it once via /auth and keeps it
/// in an HttpOnly, SameSite=Strict cookie. Without it the local server answers 401 – this protects
/// against other local users, other processes and web pages trying to reach the localhost API.
/// </summary>
public sealed class LocalAccessToken
{
    public LocalAccessToken() : this(Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32)))
    {
    }

    public LocalAccessToken(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }

    public string Value { get; }

    public bool Matches(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(candidate), Encoding.UTF8.GetBytes(Value));
    }
}
