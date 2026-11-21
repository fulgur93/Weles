using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.DataProtection;
using Serilog;
using Serilog.Events;
using Weles.App.Components;
using Weles.App.Hosting;
using Weles.App.Localization;
using Weles.App.Services;
using Weles.Infrastructure;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Agents;
using Weles.Infrastructure.Platform;

// Content root is the application directory, not the current working directory –
// WELES is started from shortcuts and installers, where the working directory is arbitrary.
var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = CommandLine.Normalize(args),
    ContentRootPath = AppContext.BaseDirectory
});

// Resolves static web assets when running from the build output; no-op in a published package.
builder.WebHost.UseStaticWebAssets();

var hostOptions = builder.Configuration.GetSection(WelesHostOptions.SectionName).Get<WelesHostOptions>() ?? new WelesHostOptions();
var paths = WelesPaths.Resolve(hostOptions.DataDirectory, hostOptions.DemoMode);
paths.EnsureCreated();

// A second launch just opens the UI of the instance that is already running.
if (hostOptions.SingleInstance && InstanceRegistry.TryGetRunningInstance(paths.InstanceFile, out var running))
{
    Console.WriteLine($"WELES już działa ({running!.BaseUrl}) – otwieram przeglądarkę.");
    using var loggerFactory = LoggerFactory.Create(l => l.AddConsole());
    if (!BrowserLauncher.TryOpen(running.LaunchUrl, loggerFactory.CreateLogger("Weles")))
    {
        Console.WriteLine($"Otwórz w przeglądarce: {running.LaunchUrl}");
    }

    return;
}

var port = PortSelector.SelectLoopbackPort(hostOptions.Port);
// The panel is never exposed to the LAN: Kestrel binds to IPv4 loopback only.
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.AddServerHeader = false;
    kestrel.Listen(IPAddress.Loopback, port);
});

// The agent endpoint (off by default): HTTPS on one chosen private address, agent protocol only.
var agentListener = AgentApiMiddleware.Configure(builder, paths);
builder.Services.AddSingleton(agentListener);

// Optional panel access from the local network (off by default): HTTPS on one private address, login required.
var panelLan = PanelLanState.Configure(builder, paths, agentListener.Active.Enabled ? agentListener.Active.Port : -1);
builder.Services.AddSingleton(panelLan);
// Host filtering stays strict: only the one LAN address is added next to 127.0.0.1/localhost.
if (panelLan.IsListening) builder.Configuration["AllowedHosts"] = $"{builder.Configuration["AllowedHosts"]};{panelLan.Active.Address}";

CultureInfo.DefaultThreadCurrentCulture = CultureInfo.DefaultThreadCurrentUICulture = CultureInfo.GetCultureInfo("pl-PL");

builder.Services.AddSerilog((_, logger) => logger
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
    .MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning)
    .MinimumLevel.Override("System.Net.Http.HttpClient", LogEventLevel.Warning)
    // On Linux/macOS keys are protected by the 0700 data directory; the "no XML encryptor" warning is expected.
    .MinimumLevel.Override("Microsoft.AspNetCore.DataProtection", LogEventLevel.Error)
    .Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File(
        Path.Combine(paths.LogsDirectory, "weles-.log"),
        rollingInterval: RollingInterval.Day,
        fileSizeLimitBytes: 10 * 1024 * 1024,
        rollOnFileSizeLimit: true,
        retainedFileCountLimit: 14,
        shared: true,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}"));

builder.Services.Configure<WelesHostOptions>(builder.Configuration.GetSection(WelesHostOptions.SectionName));
builder.Services.AddWelesInfrastructure(builder.Configuration, paths);
builder.Services.AddSingleton<LocalAccessToken>();
builder.Services.AddSingleton<Weles.Infrastructure.Integrations.ISecretProtector, DataProtectionSecretProtector>();

// Data protection keys (antiforgery, circuit state) live in the user's data directory, not in ~/.aspnet.
var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("WELES")
    .PersistKeysToFileSystem(new DirectoryInfo(paths.KeysDirectory));
if (OperatingSystem.IsWindows())
{
    dataProtection.ProtectKeysWithDpapi();
}
builder.Services.AddSingleton(sp => new RuntimeInfo(port, hostOptions.DemoMode, sp.GetRequiredService<TimeProvider>()));
builder.Services.AddSingleton(sp => new Autostart(sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<WelesHostOptions>>(), sp.GetRequiredService<RuntimeInfo>(), sp.GetRequiredService<ILogger<Autostart>>()));
builder.Services.AddScoped<ThemeState>();
builder.Services.AddSingleton<Weles.App.Localization.LanguageState>();

// RBAC: user accounts with roles; the launch token still guards the loopback panel underneath.
builder.Services.AddAuthentication(Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/login";
        o.AccessDeniedPath = "/forbidden";
        o.Cookie.Name = $"weles_auth_{port}";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Strict;
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.ExpireTimeSpan = TimeSpan.FromHours(8);
        o.SlidingExpiration = true;
        o.Events.OnValidatePrincipal = Weles.App.Security.Policies.ValidateAsync;
        // API calls get a status code instead of the login page.
        o.Events.OnRedirectToLogin = ctx => { if (ctx.Request.Path.StartsWithSegments("/api")) ctx.Response.StatusCode = 401; else ctx.Response.Redirect(ctx.RedirectUri); return Task.CompletedTask; };
        o.Events.OnRedirectToAccessDenied = ctx => { if (ctx.Request.Path.StartsWithSegments("/api")) ctx.Response.StatusCode = 403; else ctx.Response.Redirect(ctx.RedirectUri); return Task.CompletedTask; };
    });
builder.Services.AddAuthorization(Weles.App.Security.Policies.Add);
builder.Services.AddCascadingAuthenticationState();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

await app.Services.GetRequiredService<DatabaseInitializer>().InitializeAsync();
var language = app.Services.GetRequiredService<Weles.App.Localization.LanguageState>();
await language.LoadAsync();

// First: requests on the agent port are answered by the agent API and never reach the panel.
app.UseMiddleware<AgentApiMiddleware>();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}

app.UseMiddleware<LocalAccessGuardMiddleware>();
// Every request – including the Blazor circuit connection – runs in the language chosen in the UI.
app.UseRequestLocalization(options =>
{
    var cultures = Weles.App.Localization.LanguageState.Languages.Select(l => System.Globalization.CultureInfo.GetCultureInfo(l.Culture)).ToList();
    options.SupportedCultures = cultures;
    options.SupportedUICultures = cultures;
    options.SetDefaultCulture("pl-PL");
    options.RequestCultureProviders = [new Weles.App.Localization.LanguageState.Provider(language)];
});
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();
// Every API endpoint needs a signed-in user; the logs (addresses, user names) only an administrator.
app.MapGroup("").RequireAuthorization(Weles.App.Security.Policies.Admin).MapLogEndpoints();
var signedIn = app.MapGroup("").RequireAuthorization();
signedIn.MapReportEndpoints();
signedIn.MapExportEndpoints();
Weles.App.Security.AccountEndpoints.MapAccountEndpoints(app);
app.MapLanguageEndpoints();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

var token = app.Services.GetRequiredService<LocalAccessToken>();
var startupLogger = app.Services.GetRequiredService<ILogger<Program>>();

app.Lifetime.ApplicationStarted.Register(() =>
{
    var instance = new InstanceInfo(Environment.ProcessId, port, token.Value, DateTime.UtcNow);
    InstanceRegistry.Write(paths.InstanceFile, instance);

    startupLogger.LogInformation("WELES {Version} started on {Url} (demo mode: {Demo}, data: {DataDir})",
        app.Services.GetRequiredService<RuntimeInfo>().Version, instance.BaseUrl, hostOptions.DemoMode, paths.Root);
    if (agentListener.IsListening) startupLogger.LogInformation("Agent endpoint listening on {Url}", agentListener.Url);
    else if (agentListener.Active.Enabled) startupLogger.LogWarning("Agent endpoint not started: {Error}", agentListener.Error);
    if (panelLan.IsListening) startupLogger.LogWarning("Panel also available on the local network: {Url} (clients from {Subnet}, login required)", panelLan.Url, panelLan.Subnet);
    else if (panelLan.Active.Enabled) startupLogger.LogWarning("LAN access to the panel not started: {Error}", panelLan.Error);

    // The launch link holds the access token – it goes to the console only, never to the log file.
    Console.WriteLine();
    Console.WriteLine($"  WELES: {instance.LaunchUrl}");
    Console.WriteLine();

    if (hostOptions.OpenBrowser)
    {
        BrowserLauncher.TryOpen(instance.LaunchUrl, startupLogger);
    }
});

app.Lifetime.ApplicationStopping.Register(() =>
{
    startupLogger.LogInformation("WELES is stopping");
    InstanceRegistry.Remove(paths.InstanceFile);
});

await app.RunAsync();

public partial class Program;
