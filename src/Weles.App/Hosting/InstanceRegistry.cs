using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace Weles.App.Hosting;

public sealed record InstanceInfo(int ProcessId, int Port, string Token, DateTime StartedAt)
{
    public string BaseUrl => $"http://127.0.0.1:{Port}";
    public string LaunchUrl => $"{BaseUrl}{LocalAccessGuardMiddleware.AuthPath}?token={Uri.EscapeDataString(Token)}";
}

/// <summary>
/// Single-instance support. The instance file contains the access token, so on Unix it is created with mode 0600
/// inside a 0700 data directory.
/// </summary>
public static class InstanceRegistry
{
    public static bool TryGetRunningInstance(string instanceFile, out InstanceInfo? instance)
    {
        instance = null;
        if (!File.Exists(instanceFile))
        {
            return false;
        }

        try
        {
            var candidate = JsonSerializer.Deserialize<InstanceInfo>(File.ReadAllText(instanceFile));
            if (candidate is null || candidate.ProcessId == Environment.ProcessId || !IsProcessAlive(candidate.ProcessId) || !IsListening(candidate.Port))
            {
                return false;
            }

            instance = candidate;
            return true;
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static void Write(string instanceFile, InstanceInfo instance)
    {
        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        using var stream = new FileStream(instanceFile, options);
        JsonSerializer.Serialize(stream, instance);
    }

    public static void Remove(string instanceFile)
    {
        try
        {
            if (!File.Exists(instanceFile))
            {
                return;
            }

            var current = JsonSerializer.Deserialize<InstanceInfo>(File.ReadAllText(instanceFile));
            if (current?.ProcessId == Environment.ProcessId)
            {
                File.Delete(instanceFile);
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // Stale file is harmless: the next start validates PID and port before trusting it.
        }
    }

    private static bool IsProcessAlive(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static bool IsListening(int port)
    {
        try
        {
            using var client = new TcpClient();
            return client.ConnectAsync(IPAddress.Loopback, port).Wait(TimeSpan.FromMilliseconds(500)) && client.Connected;
        }
        catch (AggregateException)
        {
            return false;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
