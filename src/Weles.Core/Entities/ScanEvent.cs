namespace Weles.Core.Entities;

public enum ScanEventLevel
{
    Info = 0,
    Warning = 1,
    Error = 2
}

/// <summary>Audit trail of a scan: start, phases, warnings, stop requests, errors.</summary>
public class ScanEvent
{
    public long Id { get; set; }
    public int ScanId { get; set; }
    public Scan? Scan { get; set; }
    public DateTime Timestamp { get; set; }
    public ScanEventLevel Level { get; set; }
    public required string Message { get; set; }
}
