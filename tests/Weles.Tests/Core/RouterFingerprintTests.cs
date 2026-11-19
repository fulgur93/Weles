using System.Text;
using Weles.Core.Rules;

namespace Weles.Tests.Core;

/// <summary>Regression cases from a real TP-Link TL-WR841N v9 (wired test network, 2026-11-19).</summary>
public class RouterFingerprintTests
{
    private static HttpResponseInfo Response(string raw)
    {
        Assert.True(HttpResponseParser.TryParse(Encoding.Latin1.GetBytes(raw), out var r));
        return r;
    }

    [Theory]
    [InlineData("ipos/7.0 UPnP/1.0 TL-WR841N/9.0", "TP-Link TL-WR841N", "9.0")]
    [InlineData("Basic realm=\"TP-LINK Wireless N Router WR841N\"", "TP-Link TL-WR841N", null)]
    [InlineData("<title>Archer C6</title>", "TP-Link Archer C6", null)]
    public void Device_model_is_read_from_what_the_device_discloses(string text, string model, string? hardware)
    {
        var detected = DeviceModel.Detect(text);
        Assert.NotNull(detected);
        Assert.Equal(model, detected.Name);
        Assert.Equal(hardware, detected.HardwareVersion);
    }

    [Theory]
    [InlineData("Router Webserver")]
    [InlineData("nginx/1.24.0")]
    [InlineData("WR841 is not a model token without a vendor")]
    public void No_model_is_guessed_from_unrelated_text(string text) => Assert.Null(DeviceModel.Detect(text));

    [Fact]
    public void Basic_auth_realm_identifies_a_login_protected_router_panel()
    {
        var id = HttpFingerprinter.Identify(Response(
            "HTTP/1.1 401 N/A\r\nServer: Router Webserver\r\nConnection: close\r\nWWW-Authenticate: Basic realm=\"TP-LINK Wireless N Router WR841N\"\r\nContent-Type: text/html\r\n\r\n"), isTls: false);

        Assert.Equal("TP-Link", id.Extra["http.panel"]);
        Assert.Equal("Router", id.Extra["http.device"]);
        Assert.Equal("true", id.Extra["http.requiresAuth"]);
        Assert.Equal("true", id.Extra["http.basicOverHttp"]);
        Assert.Equal("TP-Link TL-WR841N", id.Extra["device.model"]);
    }

    [Fact]
    public void Basic_auth_over_https_is_not_flagged_as_cleartext()
    {
        var id = HttpFingerprinter.Identify(Response("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"x\"\r\n\r\n"), isTls: true);
        Assert.Equal("true", id.Extra["http.requiresAuth"]);
        Assert.False(id.Extra.ContainsKey("http.basicOverHttp"));
        Assert.Equal("login-page", id.Extra["http.panelCategory"]);
    }

    [Fact]
    public void Upnp_server_header_yields_the_model_not_the_os_as_product()
    {
        var id = HttpFingerprinter.Identify(Response("HTTP/1.1 404 Not Found\r\nSERVER: ipos/7.0 UPnP/1.0 TL-WR841N/9.0\r\nCONTENT-LENGTH: 0\r\n\r\n"), isTls: false);

        // "9.0" is the hardware revision – reporting it as a software version would mislead vulnerability matching.
        Assert.Null(id.Product);
        Assert.Null(id.Version);
        Assert.Equal("TP-Link TL-WR841N", id.Extra["device.model"]);
        Assert.Equal("9.0", id.Extra["device.hardwareVersion"]);
        Assert.Equal("true", id.Extra["http.upnp"]);
    }

    [Theory]
    [InlineData("ipos/7.0 UPnP/1.0 TL-WR841N/9.0", "TL-WR841N", "9.0")]
    [InlineData("Linux/3.10 UPnP/1.0 Cling/2.0", "Cling", "2.0")]
    [InlineData("POSIX, UPnP/1.0, Intel MicroStack/1.0.2777", "MicroStack", "1.0.2777")]
    public void Upnp_product_is_the_token_after_the_upnp_marker(string header, string product, string version)
    {
        var (p, v, _) = HttpFingerprinter.ParseServerHeader(header);
        Assert.Equal(product, p);
        Assert.Equal(version, v);
    }

    [Theory]
    [InlineData("TP-LINK TECHNOLOGIES CO.,LTD.", "TP-LINK")]
    [InlineData("Wistron InfoComm(Chongqing)Co.,Ltd.", "Wistron InfoComm")]
    [InlineData("Samsung Electronics Co.,Ltd", "Samsung")]
    [InlineData("Apple, Inc.", "Apple")]
    [InlineData("Raspberry Pi Trading Ltd", "Raspberry Pi Trading")]
    [InlineData("AVM GmbH", "AVM")]
    public void Vendor_names_are_shortened_for_automatic_names(string vendor, string expected) =>
        Assert.Equal(expected, AssetNaming.ShortVendor(vendor));

    [Fact]
    public void Automatic_name_prefers_the_disclosed_model()
    {
        Assert.Equal("TP-Link TL-WR841N (192.168.0.1)", AssetNaming.AutoName(null, AssetNaming.Label("TP-Link TL-WR841N", "TP-LINK TECHNOLOGIES CO.,LTD."), "192.168.0.1"));
        Assert.Equal("TP-LINK (192.168.0.1)", AssetNaming.AutoName(null, AssetNaming.Label(null, "TP-LINK TECHNOLOGIES CO.,LTD."), "192.168.0.1"));
        Assert.Equal("192.168.0.100", AssetNaming.AutoName(null, AssetNaming.Label(null, AssetNaming.RandomMacVendor), "192.168.0.100"));
    }

    [Fact]
    public void Undeclared_utf8_title_is_decoded()
    {
        var raw = Encoding.UTF8.GetBytes("HTTP/1.1 401 N/A\r\nContent-Type: text/html\r\n\r\n<title>Błąd logowania</title>");
        Assert.True(HttpResponseParser.TryParse(raw, out var r));
        Assert.Equal("Błąd logowania", r.Title);
    }

    [Fact]
    public void Latin1_title_without_charset_is_kept_as_latin1()
    {
        var raw = Encoding.Latin1.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<title>Café</title>");
        Assert.True(HttpResponseParser.TryParse(raw, out var r));
        Assert.Equal("Café", r.Title);
    }
}
