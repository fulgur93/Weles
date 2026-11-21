using System.Runtime.Versioning;
using Microsoft.Extensions.Options;
using Microsoft.Win32;

namespace Weles.App.Hosting;

/// <summary>
/// Starting WELES when the user logs in – per user, without administrator rights, and switched by the user (Settings or
/// the installer's option). Windows: the value "WELES" in HKCU\Software\Microsoft\Windows\CurrentVersion\Run (the same
/// value the installer writes). Linux: an XDG autostart entry ~/.config/autostart/weles.desktop. WELES then starts in
/// the background without opening the browser; opening it again (menu, desktop icon) shows the running instance.
/// </summary>
public sealed class Autostart(IOptions<WelesHostOptions> options, RuntimeInfo runtime, ILogger<Autostart> logger, string? linuxAutostartDirectory = null)
{
    public const string RunValueName = "WELES";
    public const string DesktopFileName = "weles.desktop";
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

    /// <summary>Only the normal instance can start automatically – the demo mode is started by hand.</summary>
    public bool IsSupported => !runtime.DemoMode && Environment.ProcessPath is not null && (OperatingSystem.IsWindows() || OperatingSystem.IsLinux());

    /// <summary>The command started at login: this executable, no browser, and the data directory if one was chosen.</summary>
    public string Command
    {
        get
        {
            var command = $"\"{Environment.ProcessPath}\" --no-browser";
            return options.Value.DataDirectory is { Length: > 0 } dir ? command + $" --data-dir \"{dir}\"" : command;
        }
    }

    private string DesktopFile => Path.Combine(linuxAutostartDirectory ?? DefaultLinuxDirectory(), DesktopFileName);

    public bool IsEnabled()
    {
        if (!IsSupported) return false;
        if (OperatingSystem.IsWindows()) return ReadRunValue() is not null;
        return File.Exists(DesktopFile);
    }

    public void Set(bool enabled)
    {
        if (!IsSupported) return;
        if (OperatingSystem.IsWindows())
        {
            SetRunValue(enabled);
        }
        else if (enabled)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(DesktopFile)!);
            File.WriteAllText(DesktopFile, DesktopEntry(Command));
        }
        else
        {
            File.Delete(DesktopFile);
        }

        logger.LogInformation("Autostart at login {State}", enabled ? "enabled" : "disabled");
    }

    /// <summary>The XDG autostart entry (Desktop Entry Specification; the path is quoted in Exec).</summary>
    public static string DesktopEntry(string command) => $"""
        [Desktop Entry]
        Type=Application
        Name=WELES
        Comment=WELES – Attack Surface Intelligence (start w tle, bez przeglądarki)
        Exec={command}
        Icon=weles
        Terminal=false
        X-GNOME-Autostart-enabled=true
        """ + "\n";

    private static string DefaultLinuxDirectory()
    {
        var config = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") is { Length: > 0 } xdg
            ? xdg
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        return Path.Combine(config, "autostart");
    }

    [SupportedOSPlatform("windows")]
    private static string? ReadRunValue()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        return key?.GetValue(RunValueName) as string;
    }

    [SupportedOSPlatform("windows")]
    private void SetRunValue(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey, writable: true);
        if (enabled) key.SetValue(RunValueName, Command, RegistryValueKind.String);
        else key.DeleteValue(RunValueName, throwOnMissingValue: false);
    }
}
