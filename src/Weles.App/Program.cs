using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.DataProtection;
using Serilog;
using Serilog.Events;
using Weles.App.Components;
using Weles.App.Hosting;
using Weles.App.Services;
using Weles.Infrastructure;
using Weles.Infrastructure.Database;
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

// Data protection keys (antiforgery, circuit state) live in the user's data directory, not in ~/.aspnet.
var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("WELES")
    .PersistKeysToFileSystem(new DirectoryInfo(paths.KeysDirectory));
if (OperatingSystem.IsWindows())
{
    dataProtection.ProtectKeysWithDpapi();
}
builder.Services.AddSingleton(sp => new RuntimeInfo(port, hostOptions.DemoMode, sp.GetRequiredService<TimeProvider>()));
builder.Services.AddScoped<ThemeState>();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

await app.Services.GetRequiredService<DatabaseInitializer>().InitializeAsync();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}

app.UseMiddleware<LocalAccessGuardMiddleware>();
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseAntiforgery();

app.MapStaticAssets();
app.MapLogEndpoints();
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
