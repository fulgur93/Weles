using System.Text;
using System.Text.RegularExpressions;
using Weles.Core.Models;

namespace Weles.Core.Rules;

/// <summary>Identifies "server speaks first" protocols from their greeting banner.</summary>
public static partial class BannerParser
{
    public const int MaxBannerLength = 1024;

    public static ServiceIdentification? Parse(byte[] data, int port)
    {
        if (data.Length == 0)
        {
            return null;
        }

        if (data[0] == 0xFF && data.Length >= 3 && data[1] is >= 0xFB and <= 0xFE)
        {
            return new ServiceIdentification { ServiceName = "telnet", Confidence = 85, Method = "banner", Banner = Printable(data) };
        }

        if (MySqlGreeting.TryParse(data, out var mysql))
        {
            return mysql;
        }

        return ParseText(Encoding.Latin1.GetString(data), port);
    }

    public static ServiceIdentification? ParseText(string text, int port)
    {
        var banner = Sanitize(text);
        var firstLine = banner.Split('\n', 2)[0].Trim();

        if (firstLine.StartsWith("SSH-", StringComparison.Ordinal))
        {
            return ParseSsh(firstLine);
        }

        if (RfbPattern().Match(firstLine) is { Success: true } rfb)
        {
            return new ServiceIdentification
            {
                ServiceName = "vnc", Confidence = 90, Method = "banner", Banner = firstLine,
                Extra = { ["rfb.version"] = $"{int.Parse(rfb.Groups[1].Value)}.{int.Parse(rfb.Groups[2].Value)}" }
            };
        }

        if (firstLine.StartsWith("220", StringComparison.Ordinal))
        {
            return LooksLikeSmtp(banner, port) ? ParseSmtp(banner, firstLine) : ParseFtp(banner, firstLine);
        }

        if (firstLine.StartsWith("+OK", StringComparison.Ordinal))
        {
            return ParseMail("pop3", banner, firstLine);
        }

        if (firstLine.StartsWith("* OK", StringComparison.Ordinal) || firstLine.StartsWith("* PREAUTH", StringComparison.Ordinal))
        {
            return ParseMail("imap", banner, firstLine);
        }

        if (firstLine.StartsWith("-NOAUTH", StringComparison.Ordinal) || firstLine.StartsWith("-DENIED", StringComparison.Ordinal))
        {
            return new ServiceIdentification { ServiceName = "redis", Product = "Redis", Vendor = "redis", Confidence = 80, Method = "banner", Banner = firstLine };
        }

        return null;
    }

    private static ServiceIdentification ParseSsh(string line)
    {
        // SSH-protoversion-softwareversion SP comments
        var m = SshPattern().Match(line);
        var protocol = m.Success ? m.Groups[1].Value : null;
        var software = m.Success ? m.Groups[2].Value : line;
        var comment = m.Success && m.Groups[3].Success ? m.Groups[3].Value.Trim() : null;

        string? product = null, version = null, os = null;
        var confidence = 70;

        if (OpenSshWindows().Match(software) is { Success: true } win)
        {
            (product, version, os) = ("OpenSSH", win.Groups[1].Value, "Windows");
            confidence = 95;
        }
        else if (OpenSsh().Match(software) is { Success: true } ossh)
        {
            (product, version) = ("OpenSSH", ossh.Groups[1].Value);
            confidence = 95;
        }
        else if (Dropbear().Match(software) is { Success: true } db)
        {
            (product, version) = ("Dropbear SSH", db.Groups[1].Value);
            confidence = 95;
            os ??= "Linux (embedded)";
        }
        else if (LibSsh().Match(software) is { Success: true } ls)
        {
            (product, version) = ("libssh", ls.Groups[1].Value);
            confidence = 90;
        }
        else
        {
            var parts = software.Split('_', 2);
            product = parts[0];
            version = parts.Length == 2 && char.IsDigit(parts[1].FirstOrDefault()) ? parts[1] : null;
        }

        var distro = DistributionFrom(comment);
        os ??= distro is not null ? (distro == "FreeBSD" ? "FreeBSD" : "Linux") : null;

        var result = new ServiceIdentification
        {
            ServiceName = "ssh",
            Product = product,
            Vendor = ProductCatalog.Find(product ?? "")?.CpeVendor,
            Version = version,
            Cpe = product is null ? null : ProductCatalog.Cpe(product, version),
            Banner = line,
            DistributionHint = distro,
            OsHint = os,
            Confidence = confidence,
            Method = "banner"
        };
        if (protocol is not null)
        {
            result.Extra["ssh.protocol"] = protocol;
        }

        if (comment is not null)
        {
            result.Extra["ssh.comment"] = comment;
        }

        return result;
    }

    private static bool LooksLikeSmtp(string banner, int port) =>
        SmtpWords().IsMatch(banner) || (port is 25 or 465 or 587 or 2525 && !banner.Contains("FTP", StringComparison.OrdinalIgnoreCase));

    private static ServiceIdentification ParseFtp(string banner, string firstLine)
    {
        (string Product, Regex Pattern)[] rules =
        [
            ("vsftpd", VsFtpd()),
            ("ProFTPD", ProFtpd()),
            ("FileZilla Server", FileZilla()),
            ("Pure-FTPd", PureFtpd()),
            ("Microsoft FTP Service", MsFtp()),
        ];

        foreach (var (product, pattern) in rules)
        {
            if (pattern.Match(banner) is { Success: true } m)
            {
                var version = m.Groups.Count > 1 && m.Groups[1].Success ? m.Groups[1].Value : null;
                return new ServiceIdentification
                {
                    ServiceName = "ftp", Product = product, Vendor = ProductCatalog.Find(product)?.CpeVendor, Version = version,
                    Cpe = ProductCatalog.Cpe(product, version), Banner = firstLine, Confidence = version is null ? 80 : 95, Method = "banner",
                    OsHint = product == "Microsoft FTP Service" ? "Windows" : null,
                    DistributionHint = DistributionFrom(banner)
                };
            }
        }

        return new ServiceIdentification { ServiceName = "ftp", Banner = firstLine, Confidence = 65, Method = "banner" };
    }

    private static ServiceIdentification ParseSmtp(string banner, string firstLine)
    {
        string? product = null, version = null, os = null;
        if (Exim().Match(banner) is { Success: true } exim)
        {
            (product, version) = ("Exim", exim.Groups[1].Value);
        }
        else if (Sendmail().Match(banner) is { Success: true } sm)
        {
            (product, version) = ("Sendmail", sm.Groups[1].Value);
        }
        else if (banner.Contains("Postfix", StringComparison.OrdinalIgnoreCase))
        {
            product = "Postfix";
        }
        else if (banner.Contains("Microsoft ESMTP", StringComparison.OrdinalIgnoreCase) || banner.Contains("Exchange", StringComparison.OrdinalIgnoreCase))
        {
            (product, os) = ("Microsoft Exchange", "Windows");
        }
        else if (banner.Contains("OpenSMTPD", StringComparison.OrdinalIgnoreCase))
        {
            product = "OpenSMTPD";
        }

        return new ServiceIdentification
        {
            ServiceName = "smtp", Product = product, Vendor = product is null ? null : ProductCatalog.Find(product)?.CpeVendor, Version = version,
            Cpe = product is null ? null : ProductCatalog.Cpe(product, version), Banner = firstLine,
            Confidence = product is null ? 65 : version is null ? 80 : 95, Method = "banner", OsHint = os,
            DistributionHint = DistributionFrom(banner)
        };
    }

    private static ServiceIdentification ParseMail(string service, string banner, string firstLine)
    {
        string? product = null;
        if (banner.Contains("Dovecot", StringComparison.OrdinalIgnoreCase)) product = "Dovecot";
        else if (banner.Contains("Courier", StringComparison.OrdinalIgnoreCase)) product = "Courier";
        else if (banner.Contains("Exchange", StringComparison.OrdinalIgnoreCase)) product = "Microsoft Exchange";

        return new ServiceIdentification
        {
            ServiceName = service, Product = product, Vendor = product is null ? null : ProductCatalog.Find(product)?.CpeVendor,
            Banner = firstLine, Confidence = product is null ? 65 : 80, Method = "banner",
            OsHint = product == "Microsoft Exchange" ? "Windows" : null
        };
    }

    /// <summary>Distribution markers in banners, e.g. "Ubuntu-3ubuntu0.10", "Debian-5+deb11u1", "(Ubuntu)".</summary>
    public static string? DistributionFrom(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        foreach (var distro in (string[])["Ubuntu", "Debian", "Raspbian", "FreeBSD", "CentOS", "Red Hat", "Fedora", "SUSE", "Alpine", "Amazon Linux", "Rocky", "AlmaLinux"])
        {
            if (text.Contains(distro, StringComparison.OrdinalIgnoreCase)) return distro;
        }

        if (DebRevision().IsMatch(text)) return "Debian";
        if (RhelRevision().IsMatch(text)) return "Red Hat";
        return null;
    }

    /// <summary>Keeps printable ASCII, normalizes newlines and limits the length – banners are untrusted input.</summary>
    public static string Sanitize(string text)
    {
        var sb = new StringBuilder(Math.Min(text.Length, MaxBannerLength));
        foreach (var c in text)
        {
            if (sb.Length >= MaxBannerLength) break;
            if (c == '\n' || (c >= 0x20 && c < 0x7F)) sb.Append(c);
            else if (c == '\t') sb.Append(' ');
        }

        return sb.ToString().Trim();
    }

    public static string Printable(byte[] data) =>
        Sanitize(new string(data.Take(MaxBannerLength).Select(b => b is >= 0x20 and < 0x7F or (byte)'\n' ? (char)b : '.').ToArray()));

    [GeneratedRegex(@"^SSH-(\d+\.\d+)-(\S+)(?:\s+(.*))?$")] private static partial Regex SshPattern();
    [GeneratedRegex(@"^OpenSSH_for_Windows_([\d.]+(?:p\d+)?)", RegexOptions.IgnoreCase)] private static partial Regex OpenSshWindows();
    [GeneratedRegex(@"^OpenSSH_([\d.]+(?:p\d+)?)", RegexOptions.IgnoreCase)] private static partial Regex OpenSsh();
    [GeneratedRegex(@"^dropbear_([\d.]+)", RegexOptions.IgnoreCase)] private static partial Regex Dropbear();
    [GeneratedRegex(@"^libssh[_-]?([\d.]+)", RegexOptions.IgnoreCase)] private static partial Regex LibSsh();
    [GeneratedRegex(@"^RFB (\d{3})\.(\d{3})")] private static partial Regex RfbPattern();
    [GeneratedRegex(@"\b(E?SMTP|Postfix|Exim|Sendmail|OpenSMTPD|mail service)\b", RegexOptions.IgnoreCase)] private static partial Regex SmtpWords();
    [GeneratedRegex(@"vsFTPd ([\d.]+)", RegexOptions.IgnoreCase)] private static partial Regex VsFtpd();
    [GeneratedRegex(@"ProFTPD ([\d.]+[a-z]?)", RegexOptions.IgnoreCase)] private static partial Regex ProFtpd();
    [GeneratedRegex(@"FileZilla Server(?: version)? ([\d.]+(?: beta)?)", RegexOptions.IgnoreCase)] private static partial Regex FileZilla();
    [GeneratedRegex(@"Pure-FTPd", RegexOptions.IgnoreCase)] private static partial Regex PureFtpd();
    [GeneratedRegex(@"Microsoft FTP Service", RegexOptions.IgnoreCase)] private static partial Regex MsFtp();
    [GeneratedRegex(@"Exim ([\d.]+)", RegexOptions.IgnoreCase)] private static partial Regex Exim();
    [GeneratedRegex(@"Sendmail ([\d.]+)", RegexOptions.IgnoreCase)] private static partial Regex Sendmail();
    [GeneratedRegex(@"\+deb\d+u\d+")] private static partial Regex DebRevision();
    [GeneratedRegex(@"\.el\d+")] private static partial Regex RhelRevision();
}
