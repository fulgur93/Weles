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
    [InlineData("Apache", "Apache httpd", null, null)]
    [InlineData("ApacheFoo/1.0", "ApacheFoo", "1.0", null)]
    public void Server_header(string header, string product, string? version, string? distro)
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
