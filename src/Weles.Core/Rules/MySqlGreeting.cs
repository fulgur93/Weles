using System.Diagnostics.CodeAnalysis;
using System.Text;
using Weles.Core.Models;

namespace Weles.Core.Rules;

/// <summary>Parses the MySQL/MariaDB initial handshake packet (server speaks first).</summary>
public static class MySqlGreeting
{
    public static bool TryParse(byte[] data, [NotNullWhen(true)] out ServiceIdentification? identification)
    {
        identification = null;
        if (data.Length < 6)
        {
            return false;
        }

        var payloadLength = data[0] | data[1] << 8 | data[2] << 16;
        if (payloadLength < 2 || payloadLength > 1024 || data[3] != 0)
        {
            return false;
        }

        // Error packet before handshake, e.g. "Host 'x' is not allowed to connect to this MySQL server".
        if (data[4] == 0xFF)
        {
            var message = Encoding.ASCII.GetString(data, Math.Min(7, data.Length), Math.Max(0, Math.Min(data.Length, 4 + payloadLength) - 7));
            if (!message.Contains("MySQL", StringComparison.OrdinalIgnoreCase) && !message.Contains("MariaDB", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            identification = new ServiceIdentification
            {
                ServiceName = "mysql",
                Product = message.Contains("MariaDB", StringComparison.OrdinalIgnoreCase) ? "MariaDB" : "MySQL",
                Banner = BannerParser.Sanitize(message),
                Confidence = 75,
                Method = "mysql-handshake",
                Extra = { ["mysql.access"] = "host-not-allowed" }
            };
            return true;
        }

        if (data[4] != 0x0A)
        {
            return false;
        }

        var end = Array.IndexOf(data, (byte)0, 5);
        if (end <= 5 || end - 5 > 100)
        {
            return false;
        }

        var raw = Encoding.ASCII.GetString(data, 5, end - 5);
        if (!char.IsDigit(raw[0]))
        {
            return false;
        }

        var isMaria = raw.Contains("MariaDB", StringComparison.OrdinalIgnoreCase);
        // MariaDB 10.x historically prefixes "5.5.5-" for client compatibility.
        var cleaned = raw.StartsWith("5.5.5-", StringComparison.Ordinal) && isMaria ? raw[6..] : raw;
        var version = new string(cleaned.TakeWhile(c => char.IsDigit(c) || c == '.').ToArray());
        var product = isMaria ? "MariaDB" : "MySQL";

        identification = new ServiceIdentification
        {
            ServiceName = "mysql",
            Product = product,
            Vendor = ProductCatalog.Find(product)?.CpeVendor,
            Version = version,
            Cpe = ProductCatalog.Cpe(product, version),
            Banner = BannerParser.Sanitize(raw),
            DistributionHint = BannerParser.DistributionFrom(raw),
            Confidence = 95,
            Method = "mysql-handshake"
        };
        return true;
    }
}
