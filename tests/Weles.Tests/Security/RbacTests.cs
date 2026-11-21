using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Weles.App.Hosting;
using Weles.App.Security;
using Weles.Core.Entities;
using Weles.Infrastructure.Security;
using Weles.Tests.App;
using Weles.Tests.Support;

namespace Weles.Tests.Security;

public class UserServiceTests
{
    [Fact]
    public async Task Passwords_lockout_and_the_last_administrator_are_protected()
    {
        await using var db = await TestDatabase.CreateAsync();
        var users = new UserService(db, TimeProvider.System, NullLogger<UserService>.Instance);
        Assert.NotEmpty((await users.CreateAsync("viewer", "long-enough-pass", UserRole.Viewer, null)).Errors); // the first account must be an admin
        Assert.NotEmpty((await users.CreateAsync("admin", "short", UserRole.Admin, null)).Errors);
        var (admin, _) = await users.CreateAsync("admin", "long-enough-pass", UserRole.Admin, null);
        Assert.NotNull(admin);

        await using (var ctx = db.CreateDbContext())
        {
            var stored = ctx.Users.Single().PasswordHash;
            Assert.StartsWith("pbkdf2-sha256$600000$", stored);
            Assert.DoesNotContain("long-enough-pass", stored);
        }

        var ok = await users.LoginAsync("admin", "long-enough-pass");
        Assert.NotNull(ok.User);
        Assert.True(await users.IsSessionValidAsync(admin.Id, ok.SecurityStamp));

        Assert.Equal((await users.LoginAsync("nobody", "x")).Error, (await users.LoginAsync("admin", "x")).Error); // no hint which names exist
        for (var i = 1; i < UserService.MaxFailedLogins; i++) Assert.Null((await users.LoginAsync("admin", "wrong-password")).User);
        Assert.Contains("zablokowane", (await users.LoginAsync("admin", "long-enough-pass")).Error);   // locked even with the right password

        // The last administrator can be neither demoted, nor disabled, nor deleted.
        Assert.NotEmpty(await users.SetRoleAsync(admin.Id, UserRole.Viewer, null));
        Assert.NotEmpty(await users.SetDisabledAsync(admin.Id, true, null));
        Assert.NotEmpty(await users.DeleteAsync(admin.Id, null));

        // A role change ends existing sessions.
        var (editor, _) = await users.CreateAsync("editor", "long-enough-pass", UserRole.Editor, "admin");
        var session = await users.LoginAsync("editor", "long-enough-pass");
        Assert.Empty(await users.SetRoleAsync(editor!.Id, UserRole.Viewer, "admin"));
        Assert.False(await users.IsSessionValidAsync(editor.Id, session.SecurityStamp));
    }

    [Theory]
    [InlineData("/scans", "/scans")]
    [InlineData("https://evil.example/", "/")]
    [InlineData("//evil.example/", "/")]
    [InlineData("/\\evil.example", "/")]
    [InlineData(null, "/")]
    public void Only_local_return_paths_are_followed_after_login(string? input, string expected) => Assert.Equal(expected, AccountEndpoints.LocalPath(input));
}

public class RbacPagesTests(WelesAppFactory factory) : IClassFixture<WelesAppFactory>
{
    private HttpClient Client() => factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("http://localhost") });

    [Fact]
    public async Task Without_signing_in_only_the_login_is_reachable()
    {
        var client = Client();
        await client.GetAsync($"/auth?token={Uri.EscapeDataString(factory.Services.GetRequiredService<LocalAccessToken>().Value)}");
        // No account yet: the login page sends to the first-start setup.
        var first = await client.GetAsync("/login");
        if (!await factory.Services.GetRequiredService<UserService>().AnyAsync()) Assert.Contains("setup", first.Headers.Location?.OriginalString ?? await first.Content.ReadAsStringAsync());
        await factory.SignInAsync(Client());
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/export/web.csv")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/login")).StatusCode);
        var page = await client.GetAsync("/assets");
        Assert.True(page.StatusCode == HttpStatusCode.Redirect || !(await page.Content.ReadAsStringAsync()).Contains("Inwentarz"), "the inventory must not render for an anonymous user");
        var wrong = await client.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string> { ["userName"] = "test-admin", ["password"] = "nope-nope-nope", ["returnUrl"] = "https://evil.example/" }));
        Assert.StartsWith("/login?error=", wrong.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Roles_decide_what_a_user_can_open_and_do()
    {
        var viewer = Client();
        await factory.SignInAsync(viewer, UserRole.Viewer);
        var admin = Client();
        await factory.SignInAsync(admin, UserRole.Admin);

        // Reading and exporting: every role.
        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync("/assets")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync("/api/export/results.csv")).StatusCode);
        // Administration: admin only.
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync("/api/logs/download")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/api/logs/download")).StatusCode);
        foreach (var page in (string[])["/users", "/agents", "/integrations"])
        {
            var denied = await viewer.GetAsync(page);
            Assert.Equal(HttpStatusCode.Redirect, denied.StatusCode);
            Assert.Contains("/forbidden", denied.Headers.Location!.OriginalString);
        }

        Assert.Contains("Brak uprawnień", WebUtility.HtmlDecode(await viewer.GetStringAsync("/forbidden")));
        Assert.Contains("Użytkownicy i role", WebUtility.HtmlDecode(await admin.GetStringAsync("/users")));
        // Adding scopes: Editor and up – the button is not even rendered for a viewer.
        Assert.DoesNotContain("Nowy zakres", WebUtility.HtmlDecode(await viewer.GetStringAsync("/discovery")));
        Assert.Contains("Nowy zakres", WebUtility.HtmlDecode(await admin.GetStringAsync("/discovery")));
    }
}
