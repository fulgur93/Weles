using System.Net;
using Microsoft.Extensions.Logging;
using Weles.Agent.Communication;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Networking;
using Weles.Infrastructure.Agents;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Scanning;

namespace Weles.Agent.Scanning;

/// <summary>
/// Runs one job from WELES with the shared <see cref="NetworkScanner"/> and uploads hosts in batches as they are found.
/// The agent checks the job itself as well: domain names and public addresses are refused even if the server asked.
/// </summary>
public sealed class AgentScanRunner(CentralClient client, OuiDatabase oui, LocalNetworkDiscovery network, ScanOptions options, ILogger logger)
{
    private const int BatchSize = 16;
    private static readonly TimeSpan BatchInterval = TimeSpan.FromSeconds(5);

    public async Task RunAsync(AgentJob job, CancellationTokenSource cancel, CancellationToken stopping)
    {
        var sink = new UploadSink(client, job.ScanId, cancel, logger);
        ScanStatus status;
        string? error = null;
        var progress = new ScanProgress(job.ScanId, DateTime.UtcNow);
        try
        {
            if (job.Entries.Any(e => !TargetParser.TryParse(e.Value, out var t, out _) || t.Kind == ScanTargetEntryKind.Domain))
            {
                status = ScanStatus.Failed;
                error = "Agent skanuje wyłącznie adresy, CIDR i przedziały – zadanie zawiera nazwę domeny lub nieprawidłowy wpis.";
            }
            else
            {
                logger.LogInformation("Scan {ScanId} started: scope {Scope}, ports {Ports}", job.ScanId, job.ScopeName, job.PortSpecification);
                var scanner = new NetworkScanner(oui, network, options, logger);
                // Public addresses are never allowed for an agent – the resolver skips them.
                var outcome = await scanner.RunAsync(new NetworkScanRequest(job.Entries, false, job.PortSpecification), progress, sink, cancel.Token);
                status = outcome.Error is null ? ScanStatus.Completed : ScanStatus.Failed;
                error = outcome.Error;
            }
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested)
        {
            status = ScanStatus.Cancelled;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Scan {ScanId} failed", job.ScanId);
            status = ScanStatus.Failed;
            error = ex.Message;
        }

        sink.State = sink.State with { HostsProbed = progress.HostsProbed };
        // The rest of the hosts, then the end – retried, so a short network glitch does not lose the scan.
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await sink.FlushAsync(force: true, stopping);
                await client.CompleteAsync(job.ScanId, new CompleteRequest(status, error, sink.TakeEvents(), sink.State), stopping);
                logger.LogInformation("Scan {ScanId} finished: {Status}", job.ScanId, status);
                return;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !stopping.IsCancellationRequested && attempt < 5)
            {
                logger.LogWarning("Sending the end of scan {ScanId} failed ({Error}) – retrying", job.ScanId, ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(10 * attempt), stopping);
            }
        }
    }

    private sealed class UploadSink(CentralClient client, int scanId, CancellationTokenSource cancel, ILogger logger) : IScanSink
    {
        private readonly SemaphoreSlim _lock = new(1, 1);
        private readonly List<AgentHost> _hosts = [];
        private readonly List<AgentEvent> _events = [];
        private DateTime _lastFlush = DateTime.UtcNow;

        public AgentScanState State { get; set; } = new(0, 0, 0, null, null);

        public async Task EventAsync(ScanEventLevel level, string message)
        {
            await _lock.WaitAsync();
            try
            {
                if (_events.Count < AgentProtocol.MaxEventsPerUpload) _events.Add(new AgentEvent(level, message));
            }
            finally
            {
                _lock.Release();
            }
        }

        public Task ScopeResolvedAsync(int hostsTargeted, int portCount)
        {
            State = State with { HostsTargeted = hostsTargeted, PortCount = portCount };
            return Task.CompletedTask;
        }

        public Task NetworkAsync(string? fingerprint, IReadOnlyList<SegmentInfo> segments)
        {
            State = State with { NetworkFingerprint = fingerprint, Segments = segments };
            return FlushAsync(force: true, CancellationToken.None);
        }

        public async Task HostAsync(HostScanResult host)
        {
            await _lock.WaitAsync();
            try
            {
                _hosts.Add(new AgentHost(host.Address.ToString(), host.Methods, host.RoundTripMs, host.Ttl, host.Hostname, host.MacAddress, host.IsGateway,
                    host.Classification, host.OpenPorts, host.AnnouncedServices, host.IsLocalMachine || IPAddress.IsLoopback(host.Address)));
            }
            finally
            {
                _lock.Release();
            }

            await FlushAsync(force: false, CancellationToken.None);
        }

        public List<AgentEvent> TakeEvents()
        {
            var events = _events.ToList();
            _events.Clear();
            return events;
        }

        public async Task FlushAsync(bool force, CancellationToken ct)
        {
            await _lock.WaitAsync(ct);
            try
            {
                if (!force && _hosts.Count < BatchSize && DateTime.UtcNow - _lastFlush < BatchInterval) return;
                while (_hosts.Count > 0 || force)
                {
                    var batch = _hosts.Take(Math.Min(BatchSize, AgentProtocol.MaxHostsPerUpload)).ToList();
                    ResultsResponse response;
                    try
                    {
                        response = await client.ResultsAsync(scanId, new ResultsRequest(batch, TakeEvents(), State), ct);
                    }
                    catch (Exception ex) when (!force && ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
                    {
                        // WELES unreachable for a moment: keep the hosts and try again with the next batch.
                        logger.LogWarning("Uploading results of scan {ScanId} failed ({Error}) – will retry", scanId, ex.Message);
                        _lastFlush = DateTime.UtcNow;
                        return;
                    }
                    catch (CentralException ex) when (ex.StatusCode is System.Net.HttpStatusCode.Unauthorized or System.Net.HttpStatusCode.NotFound)
                    {
                        logger.LogError("WELES no longer accepts scan {ScanId}: {Error}", scanId, ex.Message);
                        await cancel.CancelAsync();
                        throw;
                    }

                    _hosts.RemoveRange(0, batch.Count);
                    _lastFlush = DateTime.UtcNow;
                    if (response.Rejected > 0) logger.LogWarning("WELES rejected {Count} host(s) of scan {ScanId}", response.Rejected, scanId);
                    if (response.Cancel && !cancel.IsCancellationRequested)
                    {
                        logger.LogInformation("WELES asked to stop scan {ScanId}", scanId);
                        await cancel.CancelAsync();
                    }

                    force = false;
                }
            }
            finally
            {
                _lock.Release();
            }
        }
    }
}
