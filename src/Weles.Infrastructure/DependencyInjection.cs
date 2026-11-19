using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Weles.Core.Interfaces;
using Weles.Infrastructure.AI;
using Weles.Infrastructure.Database;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Scanning;
using Weles.Infrastructure.Platform;
using Weles.Infrastructure.Queries;
using Weles.Infrastructure.Settings;

namespace Weles.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddWelesInfrastructure(this IServiceCollection services, IConfiguration configuration, WelesPaths paths)
    {
        services.AddSingleton(paths);
        services.AddSingleton(TimeProvider.System);

        services.AddDbContextFactory<WelesDbContext>(options =>
            options.UseSqlite($"Data Source={paths.DatabaseFile};Default Timeout=30;Pooling=True"));

        services.AddSingleton<DatabaseInitializer>();
        services.AddSingleton<DatabaseInfoService>();
        services.AddSingleton<SettingsService>();
        services.AddSingleton<DashboardQueries>();
        services.AddSingleton<ScanQueries>();
        services.AddSingleton<AssetQueries>();
        services.AddSingleton<Assets.AssetService>();

        services.Configure<ScanOptions>(configuration.GetSection(ScanOptions.SectionName));
        services.AddSingleton<OuiDatabase>();
        services.AddSingleton<LocalNetworkDiscovery>();
        services.AddSingleton<ScanCoordinator>();
        services.AddSingleton<ScanResultWriter>();
        services.AddSingleton<ScanEngine>();
        services.AddSingleton<ScanTargetService>();
        services.AddHostedService<ScanWorker>();

        services.Configure<AiOptions>(configuration.GetSection(AiOptions.SectionName));
        services.AddHttpClient<IAiService, OllamaAiService>((sp, client) =>
        {
            var endpoint = sp.GetRequiredService<IOptions<AiOptions>>().Value.Endpoint;
            client.BaseAddress = new Uri(endpoint.EndsWith('/') ? endpoint : endpoint + "/");
        });

        return services;
    }
}
