using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Weles.App.Hosting;
using Weles.Core.Entities;
using Weles.Infrastructure.Security;
using Weles.Tests.Support;

namespace Weles.Tests.App;

public sealed class WelesAppFactory : WebApplicationFactory<Program>
{
    public string DataDirectory { get; } = TempDirectory.Create();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseContentRoot(AppContext.BaseDirectory);
        builder.UseSetting("Weles:DataDirectory", DataDirectory);
        builder.UseSetting("Weles:OpenBrowser", "false");
        builder.UseSetting("Weles:SingleInstance", "false");
        builder.UseSetting("Weles:Ai:Endpoint", "http://127.0.0.1:9"); // nothing listens – AI must degrade gracefully
        builder.UseSetting("Weles:Ai:StatusTimeoutSeconds", "1");
        builder.UseSetting("Weles:Ai:ManageEngine", "false"); // tests never start the bundled engine
    }

    public const string TestPassword = "test-password-123";
    private readonly SemaphoreSlim _users = new(1, 1);

    /// <summary>Opens the panel like a user: launch token (loopback guard), then a real sign-in with an account of the role.</summary>
    public async Task SignInAsync(HttpClient client, UserRole role = UserRole.Admin)
    {
        await client.GetAsync($"/auth?token={Uri.EscapeDataString(Services.GetRequiredService<LocalAccessToken>().Value)}");
        var users = Services.GetRequiredService<UserService>();
        var name = "test-" + role.ToString().ToLowerInvariant();
        await _users.WaitAsync();
        try
        {
            if (!await users.AnyAsync()) await users.CreateAsync("test-admin", TestPassword, UserRole.Admin, "tests");
            if ((await users.ListAsync()).All(u => u.UserName != name)) await users.CreateAsync(name, TestPassword, role, "tests");
        }
        finally
        {
            _users.Release();
        }

        var response = await client.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string> { ["userName"] = name, ["password"] = TestPassword, ["returnUrl"] = "/" }));
        if (response.StatusCode != System.Net.HttpStatusCode.Redirect || response.Headers.Location?.OriginalString != "/")
            throw new InvalidOperationException($"Sign-in failed: {response.StatusCode} {response.Headers.Location}");
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        TempDirectory.Delete(DataDirectory);
    }
}
