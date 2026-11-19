namespace Weles.Core.Rules;

/// <summary>Maps a product display name to its CPE vendor/product (as used by NVD).</summary>
public static class ProductCatalog
{
    /// <param name="Aliases">Other vendor:product pairs NVD has used for the same software (older records).</param>
    public sealed record Product(string Name, string CpeVendor, string CpeProduct, params (string Vendor, string Product)[] Aliases)
    {
        public IEnumerable<(string Vendor, string Product)> AllCpes => Aliases.Prepend((CpeVendor, CpeProduct));
    }

    private static readonly Dictionary<string, Product> ByName = new(StringComparer.OrdinalIgnoreCase)
    {
        ["OpenSSH"] = new("OpenSSH", "openbsd", "openssh"),
        ["Dropbear SSH"] = new("Dropbear SSH", "dropbear_ssh_project", "dropbear_ssh"),
        ["libssh"] = new("libssh", "libssh", "libssh"),
        ["vsftpd"] = new("vsftpd", "beasts", "vsftpd"),
        ["ProFTPD"] = new("ProFTPD", "proftpd", "proftpd"),
        ["Pure-FTPd"] = new("Pure-FTPd", "pureftpd", "pure-ftpd"),
        ["FileZilla Server"] = new("FileZilla Server", "filezilla-project", "filezilla_server"),
        ["Microsoft FTP Service"] = new("Microsoft FTP Service", "microsoft", "internet_information_services"),
        ["Postfix"] = new("Postfix", "postfix", "postfix"),
        ["Exim"] = new("Exim", "exim", "exim"),
        ["Sendmail"] = new("Sendmail", "sendmail", "sendmail"),
        ["Microsoft Exchange"] = new("Microsoft Exchange", "microsoft", "exchange_server"),
        ["Dovecot"] = new("Dovecot", "dovecot", "dovecot"),
        ["Courier"] = new("Courier", "courier-mta", "courier"),
        ["Apache httpd"] = new("Apache httpd", "apache", "http_server"),
        ["nginx"] = new("nginx", "f5", "nginx", ("nginx", "nginx")),
        ["Microsoft IIS"] = new("Microsoft IIS", "microsoft", "internet_information_services"),
        ["lighttpd"] = new("lighttpd", "lighttpd", "lighttpd"),
        ["OpenResty"] = new("OpenResty", "openresty", "openresty"),
        ["Caddy"] = new("Caddy", "caddyserver", "caddy"),
        ["Jetty"] = new("Jetty", "eclipse", "jetty"),
        ["Boa"] = new("Boa", "boa", "boa"),
        ["GoAhead"] = new("GoAhead", "embedthis", "goahead"),
        ["mini_httpd"] = new("mini_httpd", "acme", "mini_httpd"),
        ["RomPager"] = new("RomPager", "allegrosoft", "rompager"),
        ["Werkzeug"] = new("Werkzeug", "palletsprojects", "werkzeug"),
        ["gunicorn"] = new("gunicorn", "gunicorn", "gunicorn"),
        ["PHP"] = new("PHP", "php", "php"),
        ["MySQL"] = new("MySQL", "oracle", "mysql", ("mysql", "mysql")),
        ["MariaDB"] = new("MariaDB", "mariadb", "mariadb"),
        ["Redis"] = new("Redis", "redis", "redis", ("redislabs", "redis")),
        ["PostgreSQL"] = new("PostgreSQL", "postgresql", "postgresql"),
        ["Apache Tomcat"] = new("Apache Tomcat", "apache", "tomcat"),
        ["dnsmasq"] = new("dnsmasq", "thekelleys", "dnsmasq"),
        ["Unbound"] = new("Unbound", "nlnetlabs", "unbound"),
        ["BIND"] = new("BIND", "isc", "bind"),
        ["PowerDNS Recursor"] = new("PowerDNS Recursor", "powerdns", "recursor"),
        ["MiniUPnPd"] = new("MiniUPnPd", "miniupnp_project", "miniupnpd"),
        ["Kestrel"] = new("Kestrel", "microsoft", "asp.net_core"),
    };

    public static Product? Find(string name) => ByName.GetValueOrDefault(name);

    /// <summary>
    /// CPE hardware vendor/product for a model named by <see cref="DeviceModel"/>: "TP-Link TL-WR841N" →
    /// tp-link:tl-wr841n, "TP-Link Archer C6" → tp-link:archer_c6 (NVD naming). Null for vendors not covered.
    /// </summary>
    public static (string Vendor, string Product)? Hardware(string? model)
    {
        if (string.IsNullOrWhiteSpace(model)) return null;
        foreach (var (prefix, vendor) in HardwareVendors)
        {
            if (model.StartsWith(prefix + " ", StringComparison.OrdinalIgnoreCase))
            {
                var product = model[(prefix.Length + 1)..].Trim().ToLowerInvariant().Replace(' ', '_');
                return product.Length == 0 ? null : (vendor, product);
            }
        }

        return null;
    }

    /// <summary>Hardware vendors whose NVD records are bundled (their CVEs are downloaded vendor-wide).</summary>
    private static readonly (string Prefix, string CpeVendor)[] HardwareVendors = [("TP-Link", "tp-link")];

    /// <summary>Hardware/firmware vendors for which the vulnerability feed downloads all CVEs.</summary>
    public static IReadOnlyList<string> HardwareCpeVendors => HardwareVendors.Select(v => v.CpeVendor).Distinct().ToList();

    /// <summary>Distinct CPE vendor/product pairs of the software WELES can identify.</summary>
    public static IReadOnlyList<(string Vendor, string Product)> SoftwareCpes =>
        ByName.Values.SelectMany(p => p.AllCpes).Distinct().OrderBy(p => p.Vendor).ThenBy(p => p.Product).ToList();

    /// <summary>
    /// Builds a CPE 2.3 application string. OpenSSH-style "8.9p1" is split into version "8.9" and update "p1", as in NVD.
    /// Returns null when there is no reliable version – a CPE without version would match everything.
    /// </summary>
    public static string? Cpe(string productName, string? version)
    {
        if (string.IsNullOrWhiteSpace(version) || Find(productName) is not { } p)
        {
            return null;
        }

        var v = version.Trim().ToLowerInvariant();
        var update = "*";
        var m = System.Text.RegularExpressions.Regex.Match(v, @"^(\d+(?:\.\d+)*)(p\d+)$");
        if (m.Success)
        {
            v = m.Groups[1].Value;
            update = m.Groups[2].Value;
        }

        return $"cpe:2.3:a:{p.CpeVendor}:{p.CpeProduct}:{Escape(v)}:{update}:*:*:*:*:*:*";
    }

    private static string Escape(string value) => value.Replace(":", "\\:");
}
