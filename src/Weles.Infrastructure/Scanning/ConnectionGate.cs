using System.Threading.RateLimiting;

namespace Weles.Infrastructure.Scanning;

/// <summary>Bounds concurrency and connection rate for a single scan.</summary>
public sealed class ConnectionGate : IAsyncDisposable
{
    private readonly SemaphoreSlim _concurrency;
    private readonly TokenBucketRateLimiter _rate;

    public ConnectionGate(int maxConcurrent, int perSecond)
    {
        _concurrency = new SemaphoreSlim(Math.Max(1, maxConcurrent));
        var tokensPerPeriod = Math.Max(1, perSecond / 10);
        _rate = new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
        {
            TokenLimit = Math.Max(1, perSecond / 5),
            TokensPerPeriod = tokensPerPeriod,
            ReplenishmentPeriod = TimeSpan.FromMilliseconds(100),
            QueueLimit = int.MaxValue,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            AutoReplenishment = true
        });
    }

    public async Task<IDisposable> AcquireAsync(CancellationToken cancellationToken)
    {
        using var lease = await _rate.AcquireAsync(1, cancellationToken);
        await _concurrency.WaitAsync(cancellationToken);
        return new Releaser(_concurrency);
    }

    public async ValueTask DisposeAsync()
    {
        await _rate.DisposeAsync();
        _concurrency.Dispose();
    }

    private sealed class Releaser(SemaphoreSlim semaphore) : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                semaphore.Release();
            }
        }
    }
}
