using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Weles.Infrastructure.Import;

namespace Weles.Infrastructure.Scanning;

/// <param name="Path">The nmap program; null when it is not installed.</param>
public sealed record NmapStatus(string? Path, string? Version, string? Error)
{
    public bool IsAvailable => Path is not null && Error is null;
}

/// <summary>What nmap found on one host: open TCP ports and its service/version guess.</summary>
public sealed record NmapHost(IPAddress Address, IReadOnlyList<ImportedPort> Ports, string? Hostname);

public sealed class NmapException(string message) : Exception(message);

/// <summary>
/// Optional nmap engine for open ports and service versions. WELES never requires it: without nmap, or when a run fails,
/// the built-in engine scans. Nmap runs only with non-intrusive options – TCP connect scan (no raw packets, no root),
/// version detection, no NSE scripts, no OS detection, no UDP, no DNS – at WELES's rate limits, on addresses of the
/// approved scope only. Arguments are passed as a list (no shell); targets go through a temporary file of validated
/// IP addresses.
/// </summary>
public sealed partial class NmapEngine(IOptions<ScanOptions> options, ILogger<NmapEngine> logger)
{
    private NmapStatus? _status;

    /// <summary>Arguments that are never passed, whatever the configuration – they run scripts, need root or send raw packets.</summary>
    internal static readonly string[] Forbidden = ["--script", "-sC", "-A", "-O", "-sS", "-sU", "--privileged", "-sN", "-sF", "-sX"];

    public NmapStatus Status => _status ??= Detect();

    /// <summary>Looks for nmap again (e.g. after it was installed while WELES runs).</summary>
    public NmapStatus Refresh() => _status = Detect();

    private NmapStatus Detect()
    {
        var path = Locate(options.Value.NmapPath);
        if (path is null) return new NmapStatus(null, null, null);
        try
        {
            using var process = Process.Start(new ProcessStartInfo(path)
            {
                ArgumentList = { "--version" }, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
            })!;
            var output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(5000))
            {
                process.Kill(true);
                return new NmapStatus(path, null, "nmap nie odpowiedział na --version.");
            }

            var version = VersionPattern().Match(output);
            return version.Success ? new NmapStatus(path, version.Groups[1].Value, null) : new NmapStatus(path, null, "To nie wygląda na program nmap.");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return new NmapStatus(path, null, $"Nie można uruchomić nmap: {ex.Message}");
        }
    }

    internal static string? Locate(string? configured)
    {
        if (!string.IsNullOrWhiteSpace(configured)) return File.Exists(configured) ? Path.GetFullPath(configured) : null;
        var names = OperatingSystem.IsWindows() ? new[] { "nmap.exe" } : ["nmap"];
        var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).ToList();
        if (OperatingSystem.IsWindows())
        {
            foreach (var pf in new[] { Environment.GetEnvironmentVariable("ProgramFiles(x86)"), Environment.GetEnvironmentVariable("ProgramFiles") })
            {
                if (!string.IsNullOrEmpty(pf)) dirs.Add(Path.Combine(pf, "Nmap"));
            }
        }
        else
        {
            dirs.AddRange(["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/snap/bin"]);
        }

        foreach (var dir in dirs)
        {
            foreach (var name in names)
            {
                try
                {
                    var candidate = Path.Combine(dir.Trim('"'), name);
                    if (File.Exists(candidate)) return candidate;
                }
                catch (ArgumentException)
                {
                }
            }
        }

        return null;
    }

    /// <summary>The argument list for one run – also checked by tests (no scripts, no raw packets).</summary>
    internal static List<string> Arguments(string targetFile, IReadOnlyList<int> ports, ScanOptions o)
    {
        var args = new List<string>
        {
            "-sT",                         // TCP connect – the same kind of traffic as WELES's own engine, no root
            "-sV", "--version-intensity", "5",
            "-Pn",                         // hosts were already found alive by WELES
            "-n",                          // no DNS
            "--open",
            "--max-retries", "1",
            "--max-rate", Math.Max(1, o.ConnectionsPerSecond).ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--max-parallelism", Math.Max(1, o.MaxConcurrentConnections).ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--host-timeout", "10m",
            "-p", CompressPorts(ports),
            "-iL", targetFile,
            "-oX", "-"
        };
        if (args.Any(a => Forbidden.Contains(a))) throw new InvalidOperationException("Forbidden nmap option.");
        return args;
    }

    /// <summary>"1-1024,3389,8080-8090".</summary>
    internal static string CompressPorts(IReadOnlyList<int> ports)
    {
        var sorted = ports.Where(p => p is > 0 and <= 65535).Distinct().Order().ToList();
        var sb = new StringBuilder();
        for (var i = 0; i < sorted.Count; i++)
        {
            var start = sorted[i];
            while (i + 1 < sorted.Count && sorted[i + 1] == sorted[i] + 1) i++;
            if (sb.Length > 0) sb.Append(',');
            sb.Append(start == sorted[i] ? $"{start}" : $"{start}-{sorted[i]}");
        }

        return sb.ToString();
    }

    /// <summary>Runs nmap on live IPv4 hosts of one subgroup. Throws <see cref="NmapException"/> when the run fails.</summary>
    public async Task<IReadOnlyDictionary<IPAddress, NmapHost>> ScanAsync(IReadOnlyList<IPAddress> hosts, IReadOnlyList<int> ports, CancellationToken ct)
    {
        var status = Status;
        if (!status.IsAvailable) throw new NmapException(status.Error ?? "nmap nie jest zainstalowany.");
        var targets = hosts.Where(h => h.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Distinct().ToList();
        if (targets.Count == 0 || ports.Count == 0) return new Dictionary<IPAddress, NmapHost>();

        var file = Path.Combine(Path.GetTempPath(), $"weles-nmap-{Guid.NewGuid():N}.txt");
        await File.WriteAllLinesAsync(file, targets.Select(t => t.ToString()), CancellationToken.None);
        try
        {
            var info = new ProcessStartInfo(status.Path!) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            foreach (var arg in Arguments(file, ports, options.Value)) info.ArgumentList.Add(arg);
            using var process = Process.Start(info) ?? throw new NmapException("Nie udało się uruchomić nmap.");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(Math.Max(10, options.Value.NmapTimeoutSeconds)));
            var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                if (ct.IsCancellationRequested) throw;
                throw new NmapException($"nmap przekroczył limit czasu ({options.Value.NmapTimeoutSeconds} s).");
            }

            var xml = await stdout;
            var errors = (await stderr).Trim();
            if (process.ExitCode != 0) throw new NmapException($"nmap zakończył się kodem {process.ExitCode}: {Short(errors)}");
            if (errors.Length > 0) logger.LogInformation("nmap stderr: {Errors}", Short(errors));

            List<ImportedHost> parsed;
            try
            {
                parsed = ScanImportService.ParseNmap(xml, out _);
            }
            catch (ScanImportException ex)
            {
                throw new NmapException($"Nieczytelny wynik nmap: {ex.Message}");
            }

            // Only addresses WELES asked about – the output is not trusted to widen the scope.
            var asked = targets.ToHashSet();
            var result = new Dictionary<IPAddress, NmapHost>();
            foreach (var h in parsed)
            {
                if (!IPAddress.TryParse(h.Ip, out var ip) || !asked.Contains(ip)) continue;
                var allowed = ports.ToHashSet();
                result[ip] = new NmapHost(ip, h.Ports.Where(p => p.Protocol == Core.Enums.TransportProtocol.Tcp && allowed.Contains(p.Port)).ToList(), h.Hostname);
            }

            foreach (var t in targets) result.TryAdd(t, new NmapHost(t, [], null));
            return result;
        }
        finally
        {
            try { File.Delete(file); } catch (IOException) { }
        }
    }

    private static string Short(string s) => s.Length > 300 ? s[..300] + "…" : s;

    [GeneratedRegex(@"Nmap version ([0-9][0-9A-Za-z.\-]*)")]
    private static partial Regex VersionPattern();
}
