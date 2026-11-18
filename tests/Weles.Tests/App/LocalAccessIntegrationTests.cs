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

        var dashboard = await client.GetStringAsync("/");
        Assert.Contains("Brak wykonanych audytów", dashboard);

        var settings = await client.GetStringAsync("/settings");
        Assert.Contains("weles.db", settings);

        var planned = await client.GetStringAsync("/vulnerabilities");
        Assert.Contains("Planowany", planned);
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
