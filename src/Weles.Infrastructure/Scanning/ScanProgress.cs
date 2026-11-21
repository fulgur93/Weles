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

    /// <summary>The time window closed: finish the current subgroup, then pause (the scan resumes in the next window).</summary>
    public bool PauseRequested { get; set; }

    /// <summary>Why the pause was asked for – the scan event says it ("okno czasowe się skończyło", "na żądanie użytkownika").</summary>
    public string? PauseReason { get; set; }

    /// <summary>Large scopes are scanned in subgroups; progress then follows the processed addresses.</summary>
    public bool Batched { get; set; }
    public int AddressesDone { get; set; }
    /// <summary>Addresses already done before this run (a resumed scan).</summary>
    public int ResumedFrom { get; set; }
    public int Subgroup { get; set; }
    public DateTime? EstimatedEnd { get; set; }
    private int _batchSize, _batchProbedStart, _batchPortsCheckedStart, _batchPortsTotalStart;

    /// <summary>Addresses probed so far in the whole scope (including earlier runs of a resumed scan).</summary>
    public int AddressesProbed => ResumedFrom + _hostsProbed;

    public void BeginSubgroup(int number, int size)
    {
        Subgroup = number;
        _batchSize = size;
        _batchProbedStart = _hostsProbed;
        _batchPortsCheckedStart = _portsChecked;
        _batchPortsTotalStart = _portsTotal;
    }

    /// <summary>0–1 within the current subgroup: discovery is the first 30 %, ports and services the rest.</summary>
    private double SubgroupFraction()
    {
        if (_batchSize == 0) return 0;
        var discovery = Math.Min(1, (double)(_hostsProbed - _batchProbedStart) / _batchSize);
        if (Phase == ScanPhase.HostDiscovery) return 0.3 * discovery;
        var ports = _portsTotal - _batchPortsTotalStart;
        return 0.3 + 0.7 * (ports <= 0 ? 1 : Math.Min(1, (double)(_portsChecked - _batchPortsCheckedStart) / ports));
    }

    public int HostsTotal => _hostsTotal;
    public int HostsProbed => _hostsProbed;
    public int HostsAlive => _hostsAlive;
    public int HostsCompleted => _hostsCompleted;
    public int PortsTotal => _portsTotal;
    public int PortsChecked => _portsChecked;
    public int OpenPorts => _openPorts;
    public int ServicesIdentified => _services;
    public string? Activity { get => _activity; set => _activity = value; }

    public double PercentComplete => Batched && _hostsTotal > 0 && Phase is ScanPhase.HostDiscovery or ScanPhase.PortScan
        ? Math.Min(99, 100.0 * (AddressesDone + SubgroupFraction() * _batchSize) / _hostsTotal)
        : Phase switch
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
