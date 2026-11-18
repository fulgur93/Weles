using System.Collections.Concurrent;
using System.Threading.Channels;

namespace Weles.Infrastructure.Scanning;

/// <summary>Queue of approved scans, cancellation handles and live progress. Singleton.</summary>
public sealed class ScanCoordinator(TimeProvider timeProvider)
{
    private readonly Channel<int> _queue = Channel.CreateUnbounded<int>(new UnboundedChannelOptions { SingleReader = true });
    private readonly ConcurrentDictionary<int, CancellationTokenSource> _running = new();
    private readonly ConcurrentDictionary<int, ScanProgress> _progress = new();
    private readonly ConcurrentDictionary<int, bool> _stopRequested = new();

    public event Action<int>? ScanFinished;

    public ValueTask EnqueueAsync(int scanId, CancellationToken cancellationToken = default)
    {
        _progress[scanId] = new ScanProgress(scanId, timeProvider.GetUtcNow().UtcDateTime);
        return _queue.Writer.WriteAsync(scanId, cancellationToken);
    }

    public IAsyncEnumerable<int> DequeueAllAsync(CancellationToken cancellationToken) => _queue.Reader.ReadAllAsync(cancellationToken);

    /// <summary>Stops a running scan or prevents a queued one from starting. Results collected so far are kept.</summary>
    public bool RequestStop(int scanId)
    {
        _stopRequested[scanId] = true;
        if (_progress.TryGetValue(scanId, out var progress)) progress.StopRequested = true;
        if (_running.TryGetValue(scanId, out var cts))
        {
            cts.Cancel();
            return true;
        }

        return _progress.ContainsKey(scanId);
    }

    public bool IsStopRequested(int scanId) => _stopRequested.ContainsKey(scanId);

    public ScanProgress? GetProgress(int scanId) => _progress.GetValueOrDefault(scanId);

    public bool IsActive(int scanId) => _running.ContainsKey(scanId) || (_progress.TryGetValue(scanId, out var p) && p.Phase != ScanPhase.Finished);

    internal (CancellationTokenSource Cts, ScanProgress Progress) Begin(int scanId, CancellationToken hostStopping)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(hostStopping);
        _running[scanId] = cts;
        var progress = _progress.GetOrAdd(scanId, id => new ScanProgress(id, timeProvider.GetUtcNow().UtcDateTime));
        if (IsStopRequested(scanId)) cts.Cancel();
        return (cts, progress);
    }

    internal void End(int scanId)
    {
        if (_running.TryRemove(scanId, out var cts)) cts.Dispose();
        if (_progress.TryGetValue(scanId, out var progress)) progress.Phase = ScanPhase.Finished;
        _stopRequested.TryRemove(scanId, out _);
        ScanFinished?.Invoke(scanId);
    }
}
