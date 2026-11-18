using System.Text;
using Weles.Core.Enums;
using Weles.Core.Rules;

namespace Weles.Tests.Core;

public class HttpFingerprinterTests
{
    private static HttpResponseInfo Response(string raw)
    {
        Assert.True(HttpResponseParser.TryParse(Encoding.UTF8.GetBytes(raw), out var r));
        return r;
    }

    [Fact]
    public void Parses_status_headers_and_decoded_title()
    {
        var r = Response("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><head><title> Zażółć &amp; panel </title></head></html>");
        Assert.Equal(200, r.StatusCode);
        Assert.Equal("nginx/1.18.0 (Ubuntu)", r.Header("server"));
        Assert.Equal("Zażółć & panel", r.Title);
    }

    [Fact]
    public void Non_http_data_is_rejected()
    {
        Assert.False(HttpResponseParser.TryParse("SSH-2.0-OpenSSH"u8.ToArray(), out _));
    }

    [Theory]
    [InlineData("Apache/2.4.41 (Ubuntu)", "Apache httpd", "2.4.41", "Ubuntu")]
    [InlineData("nginx/1.25.3", "nginx", "1.25.3", null)]
    [InlineData("nginx", "nginx", null, null)]
    [InlineData("Microsoft-IIS/10.0", "Microsoft IIS", "10.0", null)]
    [InlineData("lighttpd/1.4.59", "lighttpd", "1.4.59", null)]
    [InlineData("Jetty(9.4.43.v20210629)", "Jetty", "9.4.43", null)]
    [InlineData("Apache-Coyote/1.1", "Apache Tomcat", null, null)]
    [InlineData("SomeServer/3.2", "SomeServer", "3.2", null)]
    [InlineData("POSIX, UPnP/1.0, Intel MicroStack/1.0.2777", "MicroStack", "1.0.2777", null)]
    [InlineData("Linux/3.10 UPnP/1.0 Cling/2.0", "Cling", "2.0", null)]
    [InlineData("Http Server", null, null, null)]
    [InlineData("BH", null, null, null)]
    [InlineData("Apache", "Apache httpd", null, null)]
    [InlineData("ApacheFoo/1.0", "ApacheFoo", "1.0", null)]
    public void Server_header(string header, string? product, string? version, string? distro)
    {
        Assert.Equal((product, version, distro), HttpFingerprinter.ParseServerHeader(header));
    }

    [Fact]
    public void Apache_identification_with_cpe_and_missing_headers()
    {
        var id = HttpFingerprinter.Identify(Response("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n<title>It works</title>"), isTls: true);

        Assert.Equal("https", id.ServiceName);
        Assert.Equal("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", id.Cpe);
        Assert.Contains("Strict-Transport-Security", id.Extra["http.missingHeaders"]);
        Assert.Equal("It works", id.Extra["http.title"]);
    }

    [Fact]
    public void Http_to_https_redirect_is_recorded()
    {
        var id = HttpFingerprinter.Identify(Response("HTTP/1.1 301 Moved\r\nLocation: https://nas.local/\r\n\r\n"), isTls: false);
        Assert.Equal("true", id.Extra["http.redirectsToHttps"]);
        Assert.False(id.Extra.ContainsKey("http.missingHeaders")); // redirects are not judged for content headers
    }

    [Theory]
    [InlineData("<title>Synology DiskStation - nas</title>", "Synology DSM", AssetType.Nas)]
    [InlineData("<title>RouterOS router configuration page</title>", "MikroTik RouterOS", AssetType.Router)]
    [InlineData("<title>phpMyAdmin</title>", "phpMyAdmin", null)]
    [InlineData("<title>HP LaserJet Pro M404</title>", "HP printer", AssetType.Printer)]
    [InlineData("<title>Home - CUPS 2.4.7</title>", "CUPS", null)]
    public void Admin_panels_and_device_uis(string body, string panel, AssetType? device)
    {
        var id = HttpFingerprinter.Identify(Response("HTTP/1.1 200 OK\r\n\r\n" + body), false);
        Assert.Equal(panel, id.Extra["http.panel"]);
        Assert.Equal(device?.ToString(), id.Extra.GetValueOrDefault("http.device"));
    }

    [Fact]
    public void Unknown_server_word_is_kept_raw_without_inventing_a_product()
    {
        var id = HttpFingerprinter.Identify(Response("HTTP/1.1 403 Forbidden\r\nServer: BH\r\n\r\n"), false);
        Assert.Null(id.Product);
        Assert.Equal("BH", id.Extra["http.server"]);
        Assert.Equal(70, id.Confidence);
    }

    [Fact]
    public void Certificate_subject_identifies_device()
    {
        var id = HttpFingerprinter.Identify(Response("HTTP/1.1 404 Not Found\r\n\r\n"), true,
            "CN=-5619267674834175474, OU=Widevine, O=Google Inc, L=Kirkland, S=Washington, C=US");
        Assert.Equal("Google Cast / Android TV", id.Extra["http.panel"]);

        var router = HttpFingerprinter.Identify(Response("HTTP/1.1 200 OK\r\n\r\n<html></html>"), true, "CN=tplinkwifi.net");
        Assert.Equal("Router", router.Extra["http.device"]);
    }

    [Fact]
    public void Upnp_endpoint_naming_a_vendor_is_not_an_admin_panel()
    {
        // Regression from a real scan: TP-Link router, port 1900.
        var id = HttpFingerprinter.Identify(Response("HTTP/1.1 404 Not Found\r\nServer: TP-LINK/TP-LINK UPnP/1.1 MiniUPnPd/2.2.2\r\n\r\n<title>404 Not Found</title>"), false);

        Assert.False(id.Extra.ContainsKey("http.panel"));
        Assert.Equal("Router", id.Extra["http.device"]);
        Assert.Equal(("MiniUPnPd", "2.2.2"), (id.Product, id.Version));
        Assert.Equal("cpe:2.3:a:miniupnp_project:miniupnpd:2.2.2:*:*:*:*:*:*:*", id.Cpe);
    }

    [Fact]
    public void Upnp_server_is_flagged()
    {
        var id = HttpFingerprinter.Identify(Response("HTTP/1.1 200 OK\r\nServer: POSIX, UPnP/1.0, Intel MicroStack/1.0.2777\r\n\r\n"), false);
        Assert.Equal("true", id.Extra["http.upnp"]);
    }

    [Fact]
    public void Generic_login_form_is_detected_without_logging_in()
    {
        var id = HttpFingerprinter.Identify(Response("HTTP/1.1 200 OK\r\n\r\n<form><input type=\"password\" name=\"p\"></form>"), false);
        Assert.Equal("login-page", id.Extra["http.panelCategory"]);
    }

    [Fact]
    public void Security_headers_present_are_not_reported()
    {
        var id = HttpFingerprinter.Identify(Response("HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=1\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: frame-ancestors 'none'\r\n\r\n"), true);
        Assert.False(id.Extra.ContainsKey("http.missingHeaders"));
    }
}

public class RedirectTests
{
    private static readonly string[] Hosts = ["192.168.0.38", "router.local"];

    [Theory]
    [InlineData("/main.html", "/main.html")]
    [InlineData("main.html", "/main.html")]
    [InlineData("http://192.168.0.38/main.html", "/main.html")]
    [InlineData("http://ROUTER.local/web/index.html?x=1", "/web/index.html?x=1")]
    [InlineData("http://192.168.0.38:8080/x", null)]          // other port
    [InlineData("https://192.168.0.38/x", null)]              // other scheme
    [InlineData("http://evil.example/x", null)]               // other host – never followed
    [InlineData("//evil.example/x", null)]                    // protocol-relative
    [InlineData("/x\r\nX-Injected: 1", null)]                 // header injection attempt
    [InlineData("/a b", null)]
    [InlineData("", null)]
    public void Only_same_origin_redirects_are_followed(string location, string? expected)
    {
        Assert.Equal(expected, HttpFingerprinter.SameOriginRedirectPath(location.Replace("\\r\\n", "\r\n"), Hosts, 80, isTls: false));
    }

    [Fact]
    public void Redirect_and_target_page_are_combined()
    {
        var first = HttpFingerprinter.Identify(Parse("HTTP/1.0 302 Redirect\r\nServer: Http Server\r\nLocation: /main.html\r\n\r\n"), false);
        var target = HttpFingerprinter.Identify(Parse("HTTP/1.0 200 OK\r\n\r\n<title>Tenda Web Master</title><input type=password>"), false);

        var combined = HttpFingerprinter.CombineRedirect(first, target);

        Assert.Equal("Tenda Web Master", combined.Extra["http.title"]);
        Assert.Equal("302", combined.Extra["http.initialStatus"]);
        Assert.Equal("/main.html", combined.Extra["http.location"]);
        Assert.Equal("Http Server", combined.Extra["http.server"]);
        Assert.Equal("login-page", combined.Extra["http.panelCategory"]);
    }

    private static HttpResponseInfo Parse(string raw)
    {
        Assert.True(HttpResponseParser.TryParse(System.Text.Encoding.ASCII.GetBytes(raw), out var r));
        return r;
    }
}

public class ProductCatalogTests
{
    [Fact]
    public void Cpe_requires_a_known_product_and_a_version()
    {
        Assert.Null(ProductCatalog.Cpe("OpenSSH", null));
        Assert.Null(ProductCatalog.Cpe("UnknownThing", "1.0"));
        Assert.Equal("cpe:2.3:a:redis:redis:7.0.11:*:*:*:*:*:*:*", ProductCatalog.Cpe("Redis", "7.0.11"));
    }
}
