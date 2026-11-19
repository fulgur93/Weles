using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Weles.Core.Enums;
using Weles.Core.Models;

namespace Weles.Core.Rules;

public sealed record HttpResponseInfo(int StatusCode, string StatusLine, IReadOnlyDictionary<string, string> Headers, string Body, string? Title)
{
    public string? Header(string name) => Headers.GetValueOrDefault(name);
}

public static partial class HttpResponseParser
{
    public static bool TryParse(byte[] raw, [NotNullWhen(true)] out HttpResponseInfo? response)
    {
        response = null;
        var text = Encoding.Latin1.GetString(raw);
        if (!text.StartsWith("HTTP/", StringComparison.Ordinal))
        {
            return false;
        }

        var headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var separatorLength = 4;
        if (headerEnd < 0)
        {
            headerEnd = text.IndexOf("\n\n", StringComparison.Ordinal);
            separatorLength = 2;
        }

        var head = headerEnd < 0 ? text : text[..headerEnd];
        var body = headerEnd < 0 ? "" : text[(headerEnd + separatorLength)..];
        var lines = head.Split('\n').Select(l => l.TrimEnd('\r')).ToArray();
        var statusParts = lines[0].Split(' ', 3);
        if (statusParts.Length < 2 || !int.TryParse(statusParts[1], out var status))
        {
            return false;
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            var name = line[..colon].Trim();
            var value = BannerParser.Sanitize(line[(colon + 1)..].Trim());
            headers[name] = headers.TryGetValue(name, out var existing) ? $"{existing}, {value}" : value;
        }

        // Declared UTF-8, or no charset at all but bytes that are valid UTF-8 (embedded servers often omit it:
        // a TP-Link router's "Błąd logowania" page has a bare "Content-Type: text/html").
        var declared = headers.TryGetValue("Content-Type", out var contentType) ? CharsetPattern().Match(contentType) : Match.Empty;
        var isUtf8 = declared.Success
            ? declared.Groups[1].Value.Equals("utf-8", StringComparison.OrdinalIgnoreCase) || declared.Groups[1].Value.Equals("utf8", StringComparison.OrdinalIgnoreCase)
            : IsStrictUtf8(Encoding.Latin1.GetBytes(body));
        if (isUtf8)
        {
            body = Encoding.UTF8.GetString(Encoding.Latin1.GetBytes(body));
        }

        response = new HttpResponseInfo(status, BannerParser.Sanitize(lines[0]), headers, body, ExtractTitle(body));
        return true;
    }

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private static bool IsStrictUtf8(byte[] bytes)
    {
        if (!bytes.Any(b => b >= 0x80)) return false;
        // A body cut at the read limit may end inside a multi-byte sequence (at most 3 dangling bytes).
        for (var cut = 0; cut <= Math.Min(3, bytes.Length - 1); cut++)
        {
            try
            {
                StrictUtf8.GetCharCount(bytes, 0, bytes.Length - cut);
                return true;
            }
            catch (DecoderFallbackException)
            {
            }
        }

        return false;
    }

    public static string? ExtractTitle(string body)
    {
        var m = TitlePattern().Match(body);
        if (!m.Success) return null;
        var title = WebUtility.HtmlDecode(WhitespacePattern().Replace(m.Groups[1].Value, " ")).Trim();
        return title.Length == 0 ? null : title.Length > 200 ? title[..200] : title;
    }

    [GeneratedRegex(@"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline)] private static partial Regex TitlePattern();
    [GeneratedRegex(@"\s+")] private static partial Regex WhitespacePattern();
    [GeneratedRegex(@"charset\s*=\s*[""']?([\w\-]+)", RegexOptions.IgnoreCase)] private static partial Regex CharsetPattern();
}

/// <summary>Identifies HTTP servers, exposed admin panels and basic header misconfigurations – without logging in.</summary>
public static partial class HttpFingerprinter
{
    private sealed record PanelRule(string Label, string Category, AssetType? Device, Regex Pattern);

    private static readonly PanelRule[] PanelRules =
    [
        new("phpMyAdmin", "admin-panel", null, Rx("phpMyAdmin")),
        new("Jenkins", "devops", null, Rx(@"\bJenkins\b|X-Jenkins")),
        new("Grafana", "devops", null, Rx(@"<title>Grafana|grafana-app")),
        new("Kibana", "devops", null, Rx(@"\bKibana\b")),
        new("Portainer", "devops", null, Rx(@"Portainer")),
        new("Proxmox VE", "admin-panel", AssetType.Server, Rx(@"Proxmox Virtual Environment|pve-")),
        new("VMware ESXi", "admin-panel", AssetType.Server, Rx(@"VMware ESXi|ID_EESX_Welcome")),
        new("pfSense", "admin-panel", AssetType.Router, Rx(@"pfSense")),
        new("OPNsense", "admin-panel", AssetType.Router, Rx(@"OPNsense")),
        new("MikroTik RouterOS", "admin-panel", AssetType.Router, Rx(@"RouterOS|mikrotik")),
        new("FRITZ!Box", "admin-panel", AssetType.Router, Rx(@"FRITZ!Box")),
        new("TP-Link", "admin-panel", AssetType.Router, Rx(@"TP-?LINK|tplinkwifi")),
        new("ASUS Router", "admin-panel", AssetType.Router, Rx(@"ASUS (Wireless )?Router|ASUSWRT")),
        new("Ubiquiti UniFi", "admin-panel", AssetType.NetworkDevice, Rx(@"UniFi")),
        new("Synology DSM", "admin-panel", AssetType.Nas, Rx(@"Synology|DiskStation")),
        new("QNAP", "admin-panel", AssetType.Nas, Rx(@"QNAP|QTS")),
        new("TrueNAS", "admin-panel", AssetType.Nas, Rx(@"TrueNAS|FreeNAS")),
        new("Webmin", "admin-panel", AssetType.Server, Rx(@"Webmin")),
        new("Cockpit", "admin-panel", AssetType.LinuxHost, Rx(@"cockpit")),
        new("Apache Tomcat", "admin-panel", AssetType.Server, Rx(@"Apache Tomcat")),
        new("HP iLO", "admin-panel", AssetType.Server, Rx(@"\biLO\b|Integrated Lights-Out")),
        new("Dell iDRAC", "admin-panel", AssetType.Server, Rx(@"iDRAC")),
        new("Zabbix", "devops", null, Rx(@"Zabbix")),
        new("Home Assistant", "device-ui", AssetType.IoTDevice, Rx(@"Home Assistant")),
        new("RabbitMQ Management", "devops", null, Rx(@"RabbitMQ Management")),
        new("Elasticsearch", "devops", null, Rx(@"You Know, for Search")),
        new("Hikvision", "device-ui", AssetType.IpCamera, Rx(@"Hikvision|DNVRS-Webs|App-webs")),
        new("Dahua", "device-ui", AssetType.IpCamera, Rx(@"Dahua|DH_WEB")),
        new("Axis camera", "device-ui", AssetType.IpCamera, Rx(@"AXIS")),
        new("Google Cast / Android TV", "device-ui", AssetType.IoTDevice, Rx(@"OU=Widevine|Google Cast|Chromecast")),
        new("HP printer", "device-ui", AssetType.Printer, Rx(@"HP (LaserJet|OfficeJet|DeskJet|Color LaserJet)|HP-ChaiSOE")),
        new("Brother printer", "device-ui", AssetType.Printer, Rx(@"Brother (HL|MFC|DCP)")),
        new("Epson printer", "device-ui", AssetType.Printer, Rx(@"EPSON")),
        // CUPS is the print server of most Linux/macOS desktops – it does not make the host a printer.
        new("CUPS", "print-server", null, Rx(@"\bCUPS\b")),
    ];

    /// <param name="certificateSubject">Subject of the TLS certificate – vendors often put the product name there (e.g. "CN=tplinkwifi.net").</param>
    public static ServiceIdentification Identify(HttpResponseInfo response, bool isTls, string? certificateSubject = null)
    {
        var server = response.Header("Server");
        var (product, version, distro) = ParseServerHeader(server);
        var extra = new Dictionary<string, string> { ["http.status"] = response.StatusCode.ToString() };

        if (response.Title is { } title) extra["http.title"] = title;
        if (server is not null) extra["http.server"] = server;
        if (response.Header("X-Powered-By") is { } powered) extra["http.poweredBy"] = powered;
        if (response.Header("Location") is { } location)
        {
            extra["http.location"] = BannerParser.Sanitize(location);
            if (!isTls && location.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                extra["http.redirectsToHttps"] = "true";
            }
        }

        var auth = response.Header("WWW-Authenticate");
        if (auth is not null)
        {
            extra["http.auth"] = auth.Length > 120 ? auth[..120] : auth;
            // HTTP Basic/Digest over plain HTTP: the browser sends the password (Basic: only base64-encoded) unencrypted.
            if (!isTls && auth.StartsWith("Basic", StringComparison.OrdinalIgnoreCase)) extra["http.basicOverHttp"] = "true";
        }

        var requiresAuth = auth is not null || response.StatusCode is 401 or 407;
        if (requiresAuth) extra["http.requiresAuth"] = "true";

        if (server is not null && server.Contains("UPnP", StringComparison.OrdinalIgnoreCase)) extra["http.upnp"] = "true";

        // The authentication realm often names the device ("TP-LINK Wireless N Router WR841N").
        var haystack = $"{response.Title}\n{server}\n{response.Header("X-Powered-By")}\n{auth}\n{certificateSubject}\n{(response.Body.Length > 20_000 ? response.Body[..20_000] : response.Body)}";
        if (DeviceModel.Detect(haystack) is { } model)
        {
            extra["device.model"] = model.Name;
            if (model.HardwareVersion is { } hw) extra["device.hardwareVersion"] = hw;
            // A model token in a UPnP Server header ("TL-WR841N/9.0") carries the hardware revision, not a software version.
            if (product is not null && model.Name.EndsWith(product, StringComparison.OrdinalIgnoreCase)) (product, version) = (null, null);
        }
        var isUpnp = extra.ContainsKey("http.upnp");
        var panel = PanelRules.FirstOrDefault(r => r.Pattern.IsMatch(haystack));
        if (panel is not null && isUpnp)
        {
            // A UPnP endpoint names the device vendor in its Server header, but it is not an admin panel.
            if (panel.Device is { } upnpDevice) extra["http.device"] = upnpDevice.ToString();
        }
        else if (panel is not null)
        {
            extra["http.panel"] = panel.Label;
            extra["http.panelCategory"] = panel.Category;
            if (panel.Device is { } device) extra["http.device"] = device.ToString();
        }
        else if (!isUpnp && requiresAuth)
        {
            extra["http.panel"] = "Panel logowania";
            extra["http.panelCategory"] = "login-page";
        }
        else if (!isUpnp && LoginForm().IsMatch(response.Body) || (response.Title is { } t && LoginTitle().IsMatch(t)))
        {
            extra["http.panel"] = "Panel logowania";
            extra["http.panelCategory"] = "login-page";
        }

        var missing = MissingSecurityHeaders(response, isTls);
        if (missing.Count > 0) extra["http.missingHeaders"] = string.Join(",", missing);

        var os = server switch
        {
            not null when server.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) => "Windows",
            _ => distro is not null ? "Linux" : null
        };

        return new ServiceIdentification
        {
            ServiceName = isTls ? "https" : "http",
            Product = product,
            Vendor = product is null ? null : ProductCatalog.Find(product)?.CpeVendor,
            Version = version,
            Cpe = product is null ? null : ProductCatalog.Cpe(product, version),
            Banner = response.StatusLine + (server is null ? "" : $" | Server: {server}"),
            DistributionHint = distro,
            OsHint = os,
            Confidence = product is null ? 70 : ProductCatalog.Find(product) is null ? (version is null ? 70 : 75) : version is null ? 80 : 90,
            Method = isTls ? "https-request" : "http-request",
            IsTls = isTls,
            Extra = extra
        };
    }

    /// <summary>
    /// Returns the path to request when <paramref name="location"/> points to the same scheme, host and port; otherwise null.
    /// Location is untrusted input: anything with control characters, spaces or an excessive length is rejected.
    /// </summary>
    public static string? SameOriginRedirectPath(string? location, IReadOnlyCollection<string> hosts, int port, bool isTls)
    {
        if (string.IsNullOrWhiteSpace(location)) return null;
        location = location.Trim();
        if (location.Length > 512 || location.Any(c => c < 0x21 || c > 0x7E)) return null;

        if (location.StartsWith("//", StringComparison.Ordinal)) return null;
        if (location.StartsWith('/')) return location;
        if (!location.Contains("://", StringComparison.Ordinal)) return "/" + location;

        if (!Uri.TryCreate(location, UriKind.Absolute, out var uri)) return null;
        var scheme = isTls ? Uri.UriSchemeHttps : Uri.UriSchemeHttp;
        if (uri.Scheme != scheme || uri.Port != port) return null;
        var host = uri.Host.Trim('[', ']');
        return hosts.Any(h => string.Equals(h, host, StringComparison.OrdinalIgnoreCase)) ? uri.PathAndQuery : null;
    }

    /// <summary>Combines the identification of the first response (a redirect) with the page it redirected to.</summary>
    public static ServiceIdentification CombineRedirect(ServiceIdentification initial, ServiceIdentification target)
    {
        var extra = new Dictionary<string, string>(target.Extra);
        foreach (var (key, value) in initial.Extra)
        {
            if (key is "http.status") extra["http.initialStatus"] = value;
            else if (key is "http.missingHeaders") continue; // judged on the content page
            else extra.TryAdd(key, value);
        }

        var useInitialProduct = target.Product is null && initial.Product is not null;
        return target with
        {
            Product = useInitialProduct ? initial.Product : target.Product,
            Vendor = useInitialProduct ? initial.Vendor : target.Vendor,
            Version = useInitialProduct ? initial.Version : target.Version,
            Cpe = useInitialProduct ? initial.Cpe : target.Cpe,
            DistributionHint = target.DistributionHint ?? initial.DistributionHint,
            OsHint = target.OsHint ?? initial.OsHint,
            Confidence = Math.Max(target.Confidence, initial.Confidence),
            Extra = extra
        };
    }

    public static (string? Product, string? Version, string? Distribution) ParseServerHeader(string? server)
    {
        if (string.IsNullOrWhiteSpace(server))
        {
            return (null, null, null);
        }

        var distro = BannerParser.DistributionFrom(server);

        // Tomcat's connector header must not be mistaken for Apache httpd.
        if (server.Contains("Apache-Coyote", StringComparison.OrdinalIgnoreCase))
        {
            return ("Apache Tomcat", null, distro);
        }

        (string Product, Regex Pattern)[] rules =
        [
            ("Apache httpd", ApacheRx()),
            ("nginx", NginxRx()),
            ("Microsoft IIS", IisRx()),
            ("lighttpd", LighttpdRx()),
            ("OpenResty", OpenRestyRx()),
            ("Caddy", CaddyRx()),
            ("Jetty", JettyRx()),
            ("Boa", BoaRx()),
            ("GoAhead", GoAheadRx()),
            ("mini_httpd", MiniHttpdRx()),
            ("RomPager", RomPagerRx()),
            ("Werkzeug", WerkzeugRx()),
            ("gunicorn", GunicornRx()),
            ("Kestrel", KestrelRx()),
            ("MiniUPnPd", MiniUpnpdRx()),
        ];

        foreach (var (product, pattern) in rules)
        {
            if (pattern.Match(server) is { Success: true } m)
            {
                var version = m.Groups.Count > 1 && m.Groups[1].Success ? m.Groups[1].Value : null;
                return (product, version, distro);
            }
        }

        // UPnP servers follow "OS/version UPnP/1.x product/version": the product is the token after the UPnP marker.
        var upnp = UpnpProductRx().Match(server);
        if (upnp.Success && !NoiseTokens.Contains(upnp.Groups[1].Value))
        {
            return (upnp.Groups[1].Value, upnp.Groups[2].Value, distro);
        }

        // Unknown server: take the first "Name/version" token that is not a protocol or OS marker,
        // e.g. "POSIX, UPnP/1.0, Intel MicroStack/1.0.2777" → MicroStack 1.0.2777. Without a version nothing is inferred –
        // a bare word like "BH" or "Http Server" is kept only as the raw header.
        foreach (Match m in GenericRx().Matches(server))
        {
            if (!NoiseTokens.Contains(m.Groups[1].Value))
            {
                return (m.Groups[1].Value, m.Groups[2].Value, distro);
            }
        }

        return (null, null, distro);
    }

    private static List<string> MissingSecurityHeaders(HttpResponseInfo r, bool isTls)
    {
        var missing = new List<string>();
        if (r.StatusCode is >= 300 and < 400) return missing; // redirects are not content pages
        if (isTls && r.Header("Strict-Transport-Security") is null) missing.Add("Strict-Transport-Security");
        if (r.Header("X-Content-Type-Options") is null) missing.Add("X-Content-Type-Options");
        var csp = r.Header("Content-Security-Policy");
        if (r.Header("X-Frame-Options") is null && (csp is null || !csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase)))
        {
            missing.Add("X-Frame-Options");
        }

        return missing;
    }

    private static Regex Rx(string pattern) => new(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));

    [GeneratedRegex(@"^Apache(?:/(\d+(?:\.\d+)*))?(?:[\s(]|$)", RegexOptions.IgnoreCase)] private static partial Regex ApacheRx();
    [GeneratedRegex(@"^nginx(?:/(\d+(?:\.\d+)*))?", RegexOptions.IgnoreCase)] private static partial Regex NginxRx();
    [GeneratedRegex(@"^Microsoft-IIS(?:/(\d+(?:\.\d+)*))?", RegexOptions.IgnoreCase)] private static partial Regex IisRx();
    [GeneratedRegex(@"^lighttpd(?:/(\d+(?:\.\d+)*))?", RegexOptions.IgnoreCase)] private static partial Regex LighttpdRx();
    [GeneratedRegex(@"^openresty(?:/(\d+(?:\.\d+)*))?", RegexOptions.IgnoreCase)] private static partial Regex OpenRestyRx();
    [GeneratedRegex(@"^Caddy", RegexOptions.IgnoreCase)] private static partial Regex CaddyRx();
    [GeneratedRegex(@"Jetty\((\d+(?:\.\d+)*)", RegexOptions.IgnoreCase)] private static partial Regex JettyRx();
    [GeneratedRegex(@"^Boa(?:/([\d.]+\w*))?", RegexOptions.IgnoreCase)] private static partial Regex BoaRx();
    [GeneratedRegex(@"^GoAhead(?:-Webs|-http)?(?:/(\d+(?:\.\d+)*))?", RegexOptions.IgnoreCase)] private static partial Regex GoAheadRx();
    [GeneratedRegex(@"^mini_httpd(?:/(\d+(?:\.\d+)*))?", RegexOptions.IgnoreCase)] private static partial Regex MiniHttpdRx();
    [GeneratedRegex(@"RomPager(?:/(\d+(?:\.\d+)*))?", RegexOptions.IgnoreCase)] private static partial Regex RomPagerRx();
    [GeneratedRegex(@"Werkzeug(?:/(\d+(?:\.\d+)*))?", RegexOptions.IgnoreCase)] private static partial Regex WerkzeugRx();
    [GeneratedRegex(@"^gunicorn(?:/(\d+(?:\.\d+)*))?", RegexOptions.IgnoreCase)] private static partial Regex GunicornRx();
    [GeneratedRegex(@"^Kestrel", RegexOptions.IgnoreCase)] private static partial Regex KestrelRx();
    [GeneratedRegex(@"MiniUPnPd/(\d+(?:\.\d+)*)", RegexOptions.IgnoreCase)] private static partial Regex MiniUpnpdRx();
    private static readonly HashSet<string> NoiseTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "UPnP", "HTTP", "DLNADOC", "DLNA", "POSIX", "Linux", "Unix", "Windows", "WindowsNT", "Darwin", "Mozilla", "Platinum", "SDK"
    };

    [GeneratedRegex(@"(?<![\w.\-])([A-Za-z][\w\-.]*)/(\d+(?:\.\d+)*[a-z]?)")] private static partial Regex GenericRx();
    [GeneratedRegex(@"UPnP/\d+(?:\.\d+)?,?\s+(?:[\w\-]+/[\d.]+,?\s+)*?([A-Za-z][\w\-.]*)/(\d+(?:\.\d+)*[a-z]?)", RegexOptions.IgnoreCase)] private static partial Regex UpnpProductRx();
    [GeneratedRegex(@"<input[^>]+type\s*=\s*[""']?password", RegexOptions.IgnoreCase)] private static partial Regex LoginForm();
    [GeneratedRegex(@"\b(log ?in|sign ?in|logowanie|admin|administration)\b", RegexOptions.IgnoreCase)] private static partial Regex LoginTitle();
}
