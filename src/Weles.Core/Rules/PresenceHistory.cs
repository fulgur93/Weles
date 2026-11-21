namespace Weles.Core.Rules;

/// <param name="Unstable">Answered in some recent covering scans and not in others, changing back and forth.</param>
/// <param name="TimeOfDay">"odpowiada tylko 18:00–24:00" when presence clearly depends on the time of day; null otherwise.</param>
/// <param name="Seen">Covering scans (of the last <see cref="PresenceHistory.Window"/>) in which the host answered.</param>
public sealed record PresenceSummary(bool Unstable, int Seen, int Covered, int ConsecutiveMisses, string? TimeOfDay)
{
    public double Ratio => Covered == 0 ? 0 : (double)Seen / Covered;
}

/// <summary>
/// How a host behaves across scans: whether it answers consistently, how many scans in a row it has missed, and whether
/// its presence depends on the time of day (e.g. a workstation that answers only during working hours). Inputs are only
/// the scans that covered the host's address on its network.
/// </summary>
public static class PresenceHistory
{
    public const int Window = 12;
    /// <summary>A host becomes inactive only after this many covering scans in a row without an answer.</summary>
    public const int DefaultInactiveAfterMisses = 3;

    private static readonly (int From, int To)[] Periods = [(0, 6), (6, 12), (12, 18), (18, 24)];

    /// <param name="history">Covering scans, newest first: (local start time, answered).</param>
    public static PresenceSummary Analyze(IReadOnlyList<(DateTime Local, bool Seen)> history)
    {
        var recent = history.Take(Window).ToList();
        var misses = recent.TakeWhile(h => !h.Seen).Count();
        var changes = recent.Zip(recent.Skip(1)).Count(p => p.First.Seen != p.Second.Seen);
        var seen = recent.Count(h => h.Seen);
        var unstable = seen > 0 && seen < recent.Count && changes >= 2;

        string? timeOfDay = null;
        var byPeriod = Periods.Select(p => (Period: p, Scans: recent.Where(h => h.Local.Hour >= p.From && h.Local.Hour < p.To).ToList()))
            .Where(x => x.Scans.Count >= 2).ToList();
        var present = byPeriod.Where(x => x.Scans.Count(h => h.Seen) >= 0.8 * x.Scans.Count).ToList();
        var absent = byPeriod.Where(x => x.Scans.All(h => !h.Seen)).ToList();
        if (present.Count > 0 && absent.Count > 0)
        {
            timeOfDay = "odpowiada w godzinach " + string.Join(", ", present.Select(x => $"{x.Period.From:00}:00–{x.Period.To:00}:00"))
                        + ", nie odpowiada " + string.Join(", ", absent.Select(x => $"{x.Period.From:00}:00–{x.Period.To:00}:00"));
        }

        return new PresenceSummary(unstable || timeOfDay is not null, seen, recent.Count, misses, timeOfDay);
    }
}
