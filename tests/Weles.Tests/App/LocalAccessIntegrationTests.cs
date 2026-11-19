using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Weles.App.Hosting;

namespace Weles.Tests.App;

public class LocalAccessIntegrationTests(WelesAppFactory factory) : IClassFixture<WelesAppFactory>
{
    private HttpClient NewClient(bool handleCookies = true) => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        HandleCookies = handleCookies,
        BaseAddress = new Uri("http://localhost")
    });

    private string Token => factory.Services.GetRequiredService<LocalAccessToken>().Value;

    private async Task<HttpClient> AuthenticatedClientAsync()
    {
        var client = NewClient();
        var auth = await client.GetAsync($"/auth?token={Uri.EscapeDataString(Token)}");
        Assert.Equal(HttpStatusCode.Redirect, auth.StatusCode);
        return client;
    }

    [Fact]
    public async Task Data_directory_and_database_are_created_on_startup()
    {
        _ = factory.Services; // forces host start
        Assert.True(File.Exists(Path.Combine(factory.DataDirectory, "data", "weles.db")));
        Assert.True(Directory.Exists(Path.Combine(factory.DataDirectory, "logs")));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/settings")]
    [InlineData("/api/logs/download")]
    [InlineData("/_framework/blazor.web.js")]
    public async Task Every_request_without_session_cookie_is_rejected(string path)
    {
        var response = await NewClient().GetAsync(path);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Wrong_token_is_rejected_and_no_cookie_is_issued()
    {
        var response = await NewClient().GetAsync("/auth?token=wrong");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task Valid_token_issues_strict_httponly_cookie_and_redirects_without_token()
    {
        var response = await NewClient(handleCookies: false).GetAsync($"/auth?token={Uri.EscapeDataString(Token)}");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/", response.Headers.Location!.OriginalString);
        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Authenticated_session_can_open_dashboard_settings_and_planned_modules()
    {
        var client = await AuthenticatedClientAsync();

        // Texts written through the dictionary are HTML-encoded by Razor ("ó" → "&#xF3;").
        var dashboard = WebUtility.HtmlDecode(await client.GetStringAsync("/"));
        Assert.Contains("Brak wykonanych audytów", dashboard);

        var settings = await client.GetStringAsync("/settings");
        Assert.Contains("weles.db", settings);

        var planned = WebUtility.HtmlDecode(await client.GetStringAsync("/risk"));
        Assert.Contains("Planowany", planned);
    }

    [Fact]
    public async Task Switching_to_english_translates_every_page()
    {
        var client = await AuthenticatedClientAsync();
        var language = factory.Services.GetRequiredService<Weles.App.Localization.LanguageState>();
        await language.SetAsync("en");
        try
        {
            foreach (var path in (string[])["/", "/assets", "/discovery", "/scans", "/vulnerabilities", "/settings", "/risk", "/ai", "/assets/999999", "/scans/999999", "/vulnerabilities/CVE-2099-0001", "/no-such-page"])
            {
                var html = await (await client.GetAsync(path)).Content.ReadAsStringAsync(); // the last one is a 404 page
                Assert.Contains("<html lang=\"en\">", html);
                var text = VisibleText(html);
                Assert.False(System.Text.RegularExpressions.Regex.IsMatch(text, "[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]"), $"{path}: {text}");
            }

            Assert.Contains("No audits yet", VisibleText(await client.GetStringAsync("/")));
            Assert.Contains("Vulnerabilities", VisibleText(await client.GetStringAsync("/vulnerabilities")));
        }
        finally
        {
            await language.SetAsync("pl");
        }

        Assert.Contains("Podatności", VisibleText(await client.GetStringAsync("/vulnerabilities")));
    }

    /// <summary>Page text without scripts, tags and the hidden reconnect/error templates.</summary>
    private static string VisibleText(string html)
    {
        html = System.Text.RegularExpressions.Regex.Replace(html, "<script.*?</script>|<style.*?</style>", "", System.Text.RegularExpressions.RegexOptions.Singleline);
        return WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Replace(html, "<[^>]+>", " "));
    }

    [Fact]
    public async Task Logs_can_be_downloaded_as_zip()
    {
        var client = await AuthenticatedClientAsync();
        var response = await client.GetAsync("/api/logs/download");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/zip", response.Content.Headers.ContentType!.MediaType);
    }

    [Fact]
    public async Task Cross_site_request_is_rejected_even_with_valid_cookie()
    {
        var client = await AuthenticatedClientAsync();
        var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.Add("Origin", "http://evil.example");

        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task Sec_fetch_cross_site_is_rejected()
    {
        var client = await AuthenticatedClientAsync();
        var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.Add("Sec-Fetch-Site", "cross-site");

        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task Non_loopback_host_header_is_rejected()
    {
        var client = await AuthenticatedClientAsync();
        var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.Host = "attacker.example";

        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(request)).StatusCode);
    }
}

public class ScanWorkerIntegrationTests(WelesAppFactory factory) : IClassFixture<WelesAppFactory>
{
    [Fact]
    public async Task Queued_scan_is_executed_by_the_background_worker_and_visible_in_ui()
    {
        await using var ssh = Weles.Tests.Support.FakeServer.Banner("SSH-2.0-OpenSSH_9.6p1\r\n");
        var targets = factory.Services.GetRequiredService<Weles.Infrastructure.Scanning.ScanTargetService>();
        var queries = factory.Services.GetRequiredService<Weles.Infrastructure.Queries.ScanQueries>();

        var id = (await targets.CreateAsync(new("Loopback", null, "127.0.0.1", null, false))).Id!.Value;
        await targets.ApproveAsync(id, confirmedAuthorization: true);
        var scanId = (await targets.StartScanAsync(id, ssh.Port.ToString())).Id!.Value;

        Weles.Infrastructure.Queries.ScanDetail? detail = null;
        for (var i = 0; i < 100; i++)
        {
            detail = await queries.GetAsync(scanId);
            if (detail!.Summary.Status is Weles.Core.Enums.ScanStatus.Completed or Weles.Core.Enums.ScanStatus.Failed) break;
            await Task.Delay(200);
        }

        Assert.Equal(Weles.Core.Enums.ScanStatus.Completed, detail!.Summary.Status);
        Assert.Equal("OpenSSH", detail.Hosts.Single().Ports.Single().Service!.Product);

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("http://localhost") });
        var token = factory.Services.GetRequiredService<LocalAccessToken>().Value;
        await client.GetAsync($"/auth?token={Uri.EscapeDataString(token)}");
        var html = System.Net.WebUtility.HtmlDecode(await client.GetStringAsync($"/scans/{scanId}"));
        Assert.Contains("127.0.0.1", html);
        Assert.Contains("Zakończony", html);
    }
}

public class AssetPagesIntegrationTests(WelesAppFactory factory) : IClassFixture<WelesAppFactory>
{
    [Fact]
    public async Task Asset_list_and_detail_render_real_inventory()
    {
        await using var ssh = Weles.Tests.Support.FakeServer.Banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n");
        var targets = factory.Services.GetRequiredService<Weles.Infrastructure.Scanning.ScanTargetService>();
        var queries = factory.Services.GetRequiredService<Weles.Infrastructure.Queries.ScanQueries>();
        var editor = factory.Services.GetRequiredService<Weles.Infrastructure.Assets.AssetService>();

        var id = (await targets.CreateAsync(new("Loopback", null, "127.0.0.1", null, false))).Id!.Value;
        await targets.ApproveAsync(id, confirmedAuthorization: true);
        var scanId = (await targets.StartScanAsync(id, ssh.Port.ToString())).Id!.Value;
        Weles.Infrastructure.Queries.ScanDetail? detail = null;
        for (var i = 0; i < 100 && detail?.Summary.Status is not Weles.Core.Enums.ScanStatus.Completed; i++)
        {
            await Task.Delay(200);
            detail = await queries.GetAsync(scanId);
        }

        var assetId = detail!.Hosts.Single().AssetId!.Value;
        await editor.UpdateAsync(assetId, new("Mój serwer testowy", null, Weles.Core.Enums.AssetCriticality.High, null));

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("http://localhost") });
        await client.GetAsync($"/auth?token={Uri.EscapeDataString(factory.Services.GetRequiredService<LocalAccessToken>().Value)}");

        var list = System.Net.WebUtility.HtmlDecode(await client.GetStringAsync("/assets"));
        Assert.Contains("Mój serwer testowy", list);
        Assert.Contains("OpenSSH 9.6p1", list);
        Assert.Contains("Nowe", list);

        var page = System.Net.WebUtility.HtmlDecode(await client.GetStringAsync($"/assets/{assetId}"));
        Assert.Contains("Mój serwer testowy", page);
        Assert.Contains("Historia obserwacji", page);
        Assert.Contains("Pierwsze wykrycie urządzenia", page);
        Assert.Contains("pakiet dystrybucji: Ubuntu", page);

        Assert.Equal(System.Net.HttpStatusCode.OK, (await client.GetAsync("/assets/999999")).StatusCode);
        Assert.Contains("nie istnieje", System.Net.WebUtility.HtmlDecode(await client.GetStringAsync("/assets/999999")));
    }
}
