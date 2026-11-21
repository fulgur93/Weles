using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Weles.Agent.Configuration;

/// <summary>
/// What the agent needs to talk to WELES after enrollment. The token is protected at rest: DPAPI (machine scope) on
/// Windows, a file readable only by the agent's account (0600 in a 0700 directory) on Linux.
/// </summary>
/// <param name="Server">"https://192.168.0.10:7443".</param>
/// <param name="Pin">SHA-256 of the WELES endpoint certificate (hex) – the only certificate the agent accepts.</param>
public sealed record AgentConfig(string Server, string Pin, int AgentId, string Name, string Token);

public static class AgentConfigStore
{
    private sealed record Stored(string Server, string Pin, int AgentId, string Name, string Token, string Protection);

    /// <summary>
    /// Windows: %ProgramData%\WELES Agent\agent.json. Linux: /etc/weles-agent/agent.json for the system service (root),
    /// otherwise ~/.config/weles-agent/agent.json.
    /// </summary>
    public static string DefaultPath()
    {
        if (OperatingSystem.IsWindows())
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WELES Agent", "agent.json");
        if (Environment.UserName == "root") return "/etc/weles-agent/agent.json";
        var config = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") is { Length: > 0 } xdg
            ? xdg
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        return Path.Combine(config, "weles-agent", "agent.json");
    }

    public static AgentConfig? Load(string path)
    {
        if (!File.Exists(path)) return null;
        var stored = JsonSerializer.Deserialize<Stored>(File.ReadAllText(path)) ?? throw new InvalidDataException("Pusty plik konfiguracji agenta.");
        var token = stored.Protection switch
        {
            "dpapi" when OperatingSystem.IsWindows() =>
                Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(stored.Token), null, DataProtectionScope.LocalMachine)),
            "file" => stored.Token,
            _ => throw new InvalidDataException("Nieobsługiwany sposób ochrony tokenu – zarejestruj agenta ponownie.")
        };
        return new AgentConfig(stored.Server, stored.Pin, stored.AgentId, stored.Name, token);
    }

    public static void Save(string path, AgentConfig config)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);
        string token, protection;
        if (OperatingSystem.IsWindows())
        {
            token = Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(config.Token), null, DataProtectionScope.LocalMachine));
            protection = "dpapi";
        }
        else
        {
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            token = config.Token;
            protection = "file";
        }

        var json = JsonSerializer.Serialize(new Stored(config.Server, config.Pin, config.AgentId, config.Name, token, protection), new JsonSerializerOptions { WriteIndented = true });
        // Created with owner-only permissions before the token is written.
        var temp = path + ".tmp";
        using (var stream = OperatingSystem.IsWindows()
                   ? new FileStream(temp, FileMode.Create, FileAccess.Write)
                   : new FileStream(temp, new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite }))
        using (var writer = new StreamWriter(stream))
        {
            writer.Write(json);
        }

        File.Move(temp, path, overwrite: true);
    }
}
