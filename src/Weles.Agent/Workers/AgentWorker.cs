using System.Net;
using Microsoft.Extensions.Options;
using Weles.Agent.Communication;
using Weles.Agent.Configuration;
using Weles.Agent.Scanning;
using Weles.Infrastructure.Agents;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Scanning;

namespace Weles.Agent.Workers;

/// <summary>Where the enrolled agent's configuration lives (set from the command line).</summary>
public sealed record AgentPaths(string ConfigFile);

/// <summary>
/// The agent service: every <see cref="AgentProtocol.PollSeconds"/> it calls WELES (heartbeat with system information);
/// when WELES hands it a job it scans and uploads results, keeping the heartbeat going so the user can stop the scan.
/// Connection problems are retried with growing pauses; a revoked agent stops asking for work.
/// </summary>
public sealed class AgentWorker(AgentPaths paths, OuiDatabase oui, LocalNetworkDiscovery network, IOptions<ScanOptions> scanOptions, ILogger<AgentWorker> logger)
    : BackgroundService
{
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var config = AgentConfigStore.Load(paths.ConfigFile);
        if (config is null)
        {
            logger.LogError("The agent is not enrolled ({File} missing). Run: weles-agent enroll --server … --pin … --code …", paths.ConfigFile);
            return;
        }

        logger.LogInformation("WELES agent {Version} \"{Name}\" (#{Id}) connecting to {Server}", SystemInfoCollector.Version, config.Name, config.AgentId, config.Server);
        using var client = new CentralClient(config.Server, config.Pin, config.Token);
        var backoff = TimeSpan.FromSeconds(AgentProtocol.PollSeconds);
        while (!stoppingToken.IsCancellationRequested)
        {
            var wait = TimeSpan.FromSeconds(AgentProtocol.PollSeconds);
            try
            {
                var response = await client.HeartbeatAsync(new HeartbeatRequest(SystemInfoCollector.Collect(network), null), stoppingToken);
                backoff = TimeSpan.FromSeconds(AgentProtocol.PollSeconds);
                if (response.Job is { } job) await RunJobAsync(client, job, stoppingToken);
                wait = TimeSpan.FromSeconds(Math.Clamp(response.PollSeconds, 5, 300));
                if (response.Job is not null) wait = TimeSpan.Zero; // ask for the next job right away
            }
            catch (CentralException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
            {
                logger.LogError("WELES rejected the agent token – the agent was revoked or deleted. Enroll it again with a new code.");
                wait = MaxBackoff;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or CentralException && !stoppingToken.IsCancellationRequested)
            {
                // Includes a certificate that does not match the pin – never ignored, only retried.
                logger.LogWarning("WELES unreachable ({Error}); next attempt in {Seconds} s", ex.Message, (int)backoff.TotalSeconds);
                wait = backoff;
                backoff = TimeSpan.FromSeconds(Math.Min(MaxBackoff.TotalSeconds, backoff.TotalSeconds * 2));
            }

            if (wait > TimeSpan.Zero) await Task.Delay(wait, stoppingToken);
        }
    }

    private async Task RunJobAsync(CentralClient client, AgentJob job, CancellationToken stoppingToken)
    {
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var runner = new AgentScanRunner(client, oui, network, scanOptions.Value, logger);
        var scan = runner.RunAsync(job, cancel, stoppingToken);

        // Heartbeats continue during the scan: they keep the agent "online" and carry the user's stop request.
        while (!scan.IsCompleted)
        {
            var tick = Task.Delay(TimeSpan.FromSeconds(AgentProtocol.PollSeconds), stoppingToken);
            if (await Task.WhenAny(scan, tick) == scan) break;
            try
            {
                var response = await client.HeartbeatAsync(new HeartbeatRequest(SystemInfoCollector.Collect(network), job.ScanId), stoppingToken);
                if (response.CancelRunning && !cancel.IsCancellationRequested)
                {
                    logger.LogInformation("WELES asked to stop scan {ScanId}", job.ScanId);
                    await cancel.CancelAsync();
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or CentralException && !stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning("Heartbeat during scan {ScanId} failed: {Error}", job.ScanId, ex.Message);
            }
        }

        await scan;
    }
}
