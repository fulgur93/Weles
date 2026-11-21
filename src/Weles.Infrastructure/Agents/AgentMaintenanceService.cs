using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Weles.Infrastructure.Agents;

/// <summary>Every minute: agent scans whose agent stopped calling are marked failed (their uploaded results are kept).</summary>
public sealed class AgentMaintenanceService(AgentService agents, ILogger<AgentMaintenanceService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        do
        {
            try
            {
                var failed = await agents.FailSilentScansAsync(stoppingToken);
                if (failed > 0) logger.LogWarning("Marked {Count} agent scan(s) as failed – the agent stopped calling", failed);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Agent maintenance failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
