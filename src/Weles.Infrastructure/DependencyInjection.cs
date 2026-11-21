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
using Weles.Infrastructure.Vulnerabilities;

namespace Weles.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddWelesInfrastructure(this IServiceCollection services, IConfiguration configuration, WelesPaths paths)
    {
        services.AddSingleton(paths);
        services.AddSingleton(TimeProvider.System);

        // Encryption at rest (SQLCipher): on by default; an existing plain database is converted once.
        var databaseKey = configuration.GetValue("Weles:Database:Encrypt", true) ? DatabaseEncryption.LoadOrCreateKey(paths) : null;
        if (databaseKey is not null) DatabaseEncryption.EncryptExisting(paths.DatabaseFile, databaseKey);
        services.AddDbContextFactory<WelesDbContext>(options => options.UseSqlite(DatabaseEncryption.ConnectionString(paths.DatabaseFile, databaseKey)));

        services.AddSingleton<DatabaseInitializer>();
        services.AddSingleton<DatabaseInfoService>();
        services.AddSingleton<SettingsService>();
        services.AddSingleton<DashboardQueries>();
        services.AddSingleton<ScanQueries>();
        services.AddSingleton<AssetQueries>();
        services.AddSingleton<VulnerabilityQueries>();
        services.AddSingleton<RiskQueries>();
        services.AddSingleton<MonitoringQueries>();
        services.AddSingleton<TopologyQueries>();
        services.AddSingleton<NetworkQueries>();
        services.AddSingleton<WebQueries>();
        services.AddSingleton<Assets.AssetService>();
        services.AddSingleton<Reports.AuditDocumentBuilder>();
        services.AddSingleton<Reports.AuditReportService>();

        services.Configure<ScanOptions>(configuration.GetSection(ScanOptions.SectionName));
        services.AddSingleton<OuiDatabase>();
        services.AddSingleton<LocalNetworkDiscovery>();
        services.AddSingleton<Scanning.NmapEngine>();
        services.AddSingleton<ICurrentNetworkProvider, CurrentNetworkProvider>();
        services.AddSingleton<ScanCoordinator>();
        services.AddSingleton<ScanResultWriter>();
        services.AddSingleton<ScanEngine>();
        services.AddSingleton<ScanTargetService>();
        services.AddHostedService<ScanWorker>();
        services.AddSingleton<ScheduleService>();
        services.AddSingleton<ScanScheduler>();
        services.AddHostedService(sp => sp.GetRequiredService<ScanScheduler>());

        services.Configure<VulnerabilityFeedOptions>(configuration.GetSection(VulnerabilityFeedOptions.SectionName));
        services.AddHttpClient<VulnerabilityFeedClient>(client =>
        {
            // Generic client name only – nothing about the user or the scanned network.
            client.DefaultRequestHeaders.UserAgent.ParseAdd("WELES-vulnerability-feed/1.0");
            client.Timeout = Timeout.InfiniteTimeSpan; // per-request timeouts in the client; EPSS/NVD pages can be large
        });
        services.AddSingleton<VulnerabilityStore>();
        services.AddSingleton<VulnerabilityMatchingService>();
        services.AddSingleton<Risk.RiskAssessmentService>();
        services.AddSingleton<Fingerprint.SignatureService>();
        services.AddSingleton<Import.ScanImportService>();
        services.AddSingleton<Security.UserService>();
        services.AddSingleton<Integrations.DefectDojoService>(sp => new Integrations.DefectDojoService(sp.GetRequiredService<IDbContextFactory<WelesDbContext>>(), sp.GetRequiredService<SettingsService>(), sp.GetRequiredService<NetworkQueries>(), sp.GetRequiredService<WebQueries>(), sp.GetRequiredService<Integrations.ISecretProtector>(), sp.GetRequiredService<TimeProvider>(), sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<Integrations.DefectDojoService>>()));
        services.AddSingleton<ScanPostProcessor>();
        services.AddSingleton<Agents.AgentService>();
        services.AddHostedService<Agents.AgentMaintenanceService>();
        services.AddSingleton<VulnerabilityDatabaseService>();
        services.AddHostedService<VulnerabilityStartupService>();

        services.Configure<External.ExternalOptions>(configuration.GetSection(External.ExternalOptions.SectionName));
        services.AddSingleton<External.DnsLookup>();
        services.AddHttpClient(External.CertificateTransparencyClient.HttpClientName, client =>
        {
            // Generic client name only; the request carries just the domain name the user asked to analyse.
            client.DefaultRequestHeaders.UserAgent.ParseAdd("WELES-ct-lookup/1.0");
            client.Timeout = Timeout.InfiniteTimeSpan; // per-request timeout in the client
        });
        services.AddSingleton<External.ICertificateTransparencySource, External.CertificateTransparencyClient>();
        services.AddSingleton<External.ExternalSurfaceService>();
        services.AddHostedService<External.ExternalStartupService>();

        services.Configure<AiOptions>(configuration.GetSection(AiOptions.SectionName));
        services.AddHttpClient<IAiService, OllamaAiService>((sp, client) =>
        {
            var endpoint = sp.GetRequiredService<IOptions<AiOptions>>().Value.Endpoint;
            client.BaseAddress = new Uri(endpoint.EndsWith('/') ? endpoint : endpoint + "/");
            client.Timeout = Timeout.InfiniteTimeSpan; // answers stream for minutes on a CPU; per-request timeouts in the service
        });
        services.AddSingleton<OllamaProcessHost>();
        services.AddHostedService(sp => sp.GetRequiredService<OllamaProcessHost>());
        services.AddSingleton<AiContextBuilder>();
        services.AddSingleton<AiAnalystService>();
        services.AddSingleton<AuditSummaryService>();

        return services;
    }
}
