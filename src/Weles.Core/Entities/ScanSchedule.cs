namespace Weles.Core.Entities;

public enum ScheduleInterval
{
    Hourly = 0,
    Every6Hours = 1,
    Daily = 2,
    Weekly = 3
}

/// <summary>
/// Automatic scans of an approved scope. A scheduled scan runs only while the scope is still approved and the computer is
/// attached to the network the scope was scanned on (same gateway MAC) – the same address range on another network is
/// never scanned automatically.
/// </summary>
public class ScanSchedule
{
    public int Id { get; set; }
    public int ScanTargetId { get; set; }
    public ScanTarget? ScanTarget { get; set; }

    public ScheduleInterval Interval { get; set; }
    public required string PortSpecification { get; set; }
    public Enums.PortEngine Engine { get; set; }
    public bool IsEnabled { get; set; } = true;

    /// <summary>Gateway fingerprint of the network the scope belongs to; null for scopes without a gateway (e.g. loopback).</summary>
    public string? NetworkFingerprint { get; set; }

    /// <summary>Time window (local time, minutes after midnight; may wrap past midnight). Null – any time.</summary>
    public int? WindowStartMinute { get; set; }
    public int? WindowEndMinute { get; set; }

    public Core.Scheduling.TimeWindow? Window => WindowStartMinute is { } start && WindowEndMinute is { } end ? new Core.Scheduling.TimeWindow(start, end) : null;

    public DateTime NextRunAt { get; set; }
    public DateTime? LastRunAt { get; set; }
    public int? LastScanId { get; set; }

    /// <summary>Outcome of the last attempt (started, or why it was skipped).</summary>
    public string? LastResult { get; set; }
    public DateTime CreatedAt { get; set; }

    public static TimeSpan Length(ScheduleInterval interval) => interval switch
    {
        ScheduleInterval.Hourly => TimeSpan.FromHours(1),
        ScheduleInterval.Every6Hours => TimeSpan.FromHours(6),
        ScheduleInterval.Daily => TimeSpan.FromDays(1),
        _ => TimeSpan.FromDays(7)
    };
}
