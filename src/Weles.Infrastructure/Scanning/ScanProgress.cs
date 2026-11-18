namespace Weles.Infrastructure.Scanning;

public enum ScanPhase
{
    Queued,
    ResolvingScope,
    HostDiscovery,
    PortScan,
    Finishing,
    Finished
}

/// <summary>Live, in-memory progress of a running scan (thread-safe counters).</summary>
public sealed class ScanProgress(int scanId, DateTime startedAt)
{
    private int _hostsTotal, _hostsProbed, _hostsAlive, _hostsCompleted, _portsTotal, _portsChecked, _openPorts, _services;
    private volatile string? _activity;

    public int ScanId { get; } = scanId;
    public DateTime StartedAt { get; } = startedAt;
    public ScanPhase Phase { get; set; } = ScanPhase.Queued;
    public bool StopRequested { get; set; }

    public int HostsTotal => _hostsTotal;
    public int HostsProbed => _hostsProbed;
    public int HostsAlive => _hostsAlive;
    public int HostsCompleted => _hostsCompleted;
    public int PortsTotal => _portsTotal;
    public int PortsChecked => _portsChecked;
    public int OpenPorts => _openPorts;
    public int ServicesIdentified => _services;
    public string? Activity { get => _activity; set => _activity = value; }

    public double PercentComplete => Phase switch
    {
        ScanPhase.Queued or ScanPhase.ResolvingScope => 0,
        ScanPhase.HostDiscovery => _hostsTotal == 0 ? 0 : 30.0 * _hostsProbed / _hostsTotal,
        ScanPhase.PortScan => 30 + (_portsTotal == 0 ? 70 : 70.0 * _portsChecked / _portsTotal),
        _ => 100
    };

    public void SetHostsTotal(int value) => Interlocked.Exchange(ref _hostsTotal, value);
    public void HostProbed(bool alive)
    {
        Interlocked.Increment(ref _hostsProbed);
        if (alive) Interlocked.Increment(ref _hostsAlive);
    }

    public void AddAlive(int count) => Interlocked.Add(ref _hostsAlive, count);
    public void SetPortsTotal(int value) => Interlocked.Exchange(ref _portsTotal, value);
    public void PortChecked(bool open)
    {
        Interlocked.Increment(ref _portsChecked);
        if (open) Interlocked.Increment(ref _openPorts);
    }

    public void ServiceIdentified() => Interlocked.Increment(ref _services);
    public void HostCompleted() => Interlocked.Increment(ref _hostsCompleted);
}
