using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace Weles.Infrastructure.Scanning;

/// <summary>
/// Observed path to a host of the approved scope: the routers that answer on the way. Windows – ICMP echo with a growing
/// TTL (works without administrator rights). Linux/macOS – .NET reports an expired TTL only with raw-socket rights, so the
/// system's <c>tracepath</c> (iputils, unprivileged UDP) is used, started without a shell with the validated address as
/// its only free argument; without it the ICMP method is tried. Probes go only to the target address; at most
/// <c>maxHops</c> probes, one at a time.
/// </summary>
public static partial class TracerouteProbe
{
    /// <returns>Router addresses in hop order, the target last when it was reached; empty when nothing answered.</returns>
    public static async Task<IReadOnlyList<string>> TraceAsync(IPAddress target, int maxHops, int hopTimeoutMs, CancellationToken ct)
    {
        maxHops = Math.Clamp(maxHops, 1, 16);
        if (!OperatingSystem.IsWindows() && Locate() is { } tracepath)
        {
            var viaTool = await TracepathAsync(tracepath, target, maxHops, hopTimeoutMs, ct);
            if (viaTool is not null) return viaTool;
        }

        return await IcmpAsync(target, maxHops, hopTimeoutMs, ct);
    }

    private static async Task<IReadOnlyList<string>> IcmpAsync(IPAddress target, int maxHops, int hopTimeoutMs, CancellationToken ct)
    {
        var path = new List<string>();
        for (var ttl = 1; ttl <= maxHops; ttl++)
        {
            ct.ThrowIfCancellationRequested();
            PingReply reply;
            try
            {
                using var ping = new Ping();
                reply = await ping.SendPingAsync(target, TimeSpan.FromMilliseconds(hopTimeoutMs), null, new PingOptions(ttl, true), ct);
            }
            catch (Exception ex) when (ex is PingException or PlatformNotSupportedException or InvalidOperationException)
            {
                break;
            }

            if (reply.Status == IPStatus.Success)
            {
                path.Add(reply.Address.ToString());
                break;
            }

            // Windows reports TtlExpired; on Linux via the ping utility the same ICMP message arrives as TimeExceeded.
            if (reply.Status is IPStatus.TtlExpired or IPStatus.TimeExceeded && !reply.Address.Equals(IPAddress.Any)) path.Add(reply.Address.ToString());
        }

        return path;
    }

    /// <returns>null when tracepath could not be used (then ICMP is tried).</returns>
    private static async Task<IReadOnlyList<string>?> TracepathAsync(string tool, IPAddress target, int maxHops, int hopTimeoutMs, CancellationToken ct)
    {
        var info = new ProcessStartInfo(tool) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        info.ArgumentList.Add("-n");
        info.ArgumentList.Add("-m");
        info.ArgumentList.Add(maxHops.ToString(System.Globalization.CultureInfo.InvariantCulture));
        info.ArgumentList.Add(target.ToString());
        try
        {
            using var process = Process.Start(info);
            if (process is null) return null;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(3000, maxHops * (hopTimeoutMs + 1500))));
            var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                if (ct.IsCancellationRequested) throw;
            }

            string text;
            try
            {
                text = await output; // the stream may still be draining after the process has exited
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                text = "";
            }

            return ParseTracepath(text, target);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// " 1:  192.168.0.1   0.512ms", " 2:  no reply", " 3:  10.0.0.7   1.1ms reached" → ["192.168.0.1", "10.0.0.7"].
    /// Only IPv4 addresses are taken; one per hop, in hop order.
    /// </summary>
    internal static IReadOnlyList<string> ParseTracepath(string output, IPAddress target)
    {
        var byHop = new SortedDictionary<int, string>();
        foreach (var line in output.Split('\n'))
        {
            var m = HopLine().Match(line);
            if (!m.Success || !int.TryParse(m.Groups[1].Value, out var hop) || !IPAddress.TryParse(m.Groups[2].Value, out var ip)) continue;
            byHop.TryAdd(hop, ip.ToString());
        }

        var path = new List<string>();
        foreach (var ip in byHop.Values)
        {
            if (path.Count == 0 || path[^1] != ip) path.Add(ip);
            if (ip == target.ToString()) break;
        }

        return path;
    }

    private static string? Locate()
    {
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).Concat(["/usr/bin", "/bin", "/usr/sbin"]))
        {
            var candidate = Path.Combine(dir, "tracepath");
            if (File.Exists(candidate)) return candidate;
        }

        return null;
    }

    [GeneratedRegex(@"^\s*(\d+)\??:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")]
    private static partial Regex HopLine();
}
