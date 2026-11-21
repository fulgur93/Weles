namespace Weles.Core.Scheduling;

/// <summary>
/// A daily time window in local time, e.g. 22:00–06:00 (wraps past midnight). Scheduled scans start only inside it, and a
/// scan still running when it closes is paused at the next subgroup boundary and resumed in the next window.
/// </summary>
public sealed record TimeWindow(int StartMinute, int EndMinute)
{
    public bool IsValid => StartMinute is >= 0 and < 1440 && EndMinute is >= 0 and < 1440 && StartMinute != EndMinute;

    public bool Contains(DateTime local)
    {
        var minute = local.Hour * 60 + local.Minute;
        return StartMinute < EndMinute ? minute >= StartMinute && minute < EndMinute : minute >= StartMinute || minute < EndMinute;
    }

    /// <summary>"22:00–06:00".</summary>
    public override string ToString() => $"{StartMinute / 60:00}:{StartMinute % 60:00}–{EndMinute / 60:00}:{EndMinute % 60:00}";

    public static bool TryParse(string? start, string? end, out TimeWindow? window)
    {
        window = null;
        if (string.IsNullOrWhiteSpace(start) && string.IsNullOrWhiteSpace(end)) return true;
        if (!TimeOnly.TryParse(start, System.Globalization.CultureInfo.InvariantCulture, out var s) || !TimeOnly.TryParse(end, System.Globalization.CultureInfo.InvariantCulture, out var e)) return false;
        window = new TimeWindow(s.Hour * 60 + s.Minute, e.Hour * 60 + e.Minute);
        return window.IsValid;
    }
}
