using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Weles.App.Hosting;

namespace Weles.Tests.Security;

/// <summary>Optional LAN access to the panel: off by default, one private address, own subnet only, login always.</summary>
public class PanelLanTests
{
    private static readonly PanelLanState Lan = new(new PanelLanSettings(true, "192.168.0.10", 5443), null, "192.168.0.0/24", "AA:BB");

    [Theory]
    [InlineData("192.168.0.10", 5443, null)]
    [InlineData("10.1.2.3", 8443, null)]
    [InlineData("0.0.0.0", 5443, "konkretny")]
    [InlineData("127.0.0.1", 5443, "konkretny")]
    [InlineData("8.8.8.8", 5443, "publiczny")]
    [InlineData("fe80::1", 5443, "IPv4")]
    [InlineData("192.168.0.10", 80, "1024")]
    [InlineData("192.168.0.10", 7443, "agentów")]
    public void Only_one_private_address_and_a_free_port_are_accepted(string address, int port, string? error)
    {
        var result = new PanelLanSettings(true, address, port).Validate(agentPort: 7443);
        if (error is null) Assert.Null(result);
        else Assert.Contains(error, result);
    }

    [Fact]
    public void Disabled_by_default_and_clients_only_from_the_same_subnet()
    {
        Assert.False(new PanelLanSettings().Enabled);
        Assert.False(new PanelLanState(new PanelLanSettings(), null, null, null).IsListening);
        Assert.True(Lan.AllowsClient(IPAddress.Parse("192.168.0.77")));
        Assert.True(Lan.AllowsClient(IPAddress.Parse("::ffff:192.168.0.77")));
        Assert.False(Lan.AllowsClient(IPAddress.Parse("192.168.1.77")));
        Assert.False(Lan.AllowsClient(IPAddress.Parse("10.0.0.1")));
        Assert.False(Lan.AllowsClient(null));
        Assert.True(Lan.IsExpectedHost(new HostString("192.168.0.10", 5443)));
        Assert.False(Lan.IsExpectedHost(new HostString("evil.example", 5443)));   // DNS rebinding
        Assert.False(Lan.IsExpectedHost(new HostString("192.168.0.10", 5090)));
    }

    private static async Task<(int Status, bool Passed, bool Aborted)> SendAsync(string remote, string host, string path, string? origin = null)
    {
        var passed = false;
        var middleware = new LocalAccessGuardMiddleware(_ => { passed = true; return Task.CompletedTask; }, new LocalAccessToken("token-value-0123456789"),
            Microsoft.Extensions.Options.Options.Create(new WelesHostOptions()), Lan, NullLogger<LocalAccessGuardMiddleware>.Instance);
        var context = new DefaultHttpContext();
        context.Connection.LocalIpAddress = IPAddress.Parse("192.168.0.10");
        context.Connection.LocalPort = 5443;
        context.Connection.RemoteIpAddress = IPAddress.Parse(remote);
        context.Request.Host = HostString.FromUriComponent(host);
        context.Request.Path = path;
        context.Request.Scheme = "https";
        if (origin is not null) context.Request.Headers.Origin = origin;
        var aborted = false;
        context.RequestAborted.Register(() => aborted = true);
        context.Features.Set<Microsoft.AspNetCore.Http.Features.IHttpRequestLifetimeFeature>(new Lifetime(() => aborted = true));
        await middleware.InvokeAsync(context);
        return (context.Response.StatusCode, passed, aborted);
    }

    private sealed class Lifetime(Action abort) : Microsoft.AspNetCore.Http.Features.IHttpRequestLifetimeFeature
    {
        public CancellationToken RequestAborted { get; set; }
        public void Abort() => abort();
    }

    [Fact]
    public async Task Lan_requests_go_to_the_login_and_never_to_local_only_paths()
    {
        // From the subnet with the right Host: passed on – the normal login (accounts, roles) decides; no launch token needed.
        var ok = await SendAsync("192.168.0.77", "192.168.0.10:5443", "/");
        Assert.True(ok.Passed);

        Assert.True((await SendAsync("192.168.1.5", "192.168.0.10:5443", "/")).Aborted);              // another subnet
        Assert.Equal(400, (await SendAsync("192.168.0.77", "weles.attacker.example:5443", "/")).Status); // DNS rebinding
        Assert.Equal(403, (await SendAsync("192.168.0.77", "192.168.0.10:5443", "/", "https://evil.example")).Status);
        Assert.Equal(404, (await SendAsync("192.168.0.77", "192.168.0.10:5443", "/auth")).Status);     // launch token only on 127.0.0.1
        Assert.Equal(404, (await SendAsync("192.168.0.77", "192.168.0.10:5443", "/setup")).Status);    // first admin only locally
        Assert.Equal(404, (await SendAsync("192.168.0.77", "192.168.0.10:5443", "/account/setup")).Status);
    }
}
