namespace Weles.Infrastructure.Platform;

/// <summary>
/// Locations of user data. Nothing is ever written to the installation directory.
/// Windows: %LOCALAPPDATA%\Weles, Linux: $XDG_DATA_HOME/weles (~/.local/share/weles).
/// </summary>
public sealed class WelesPaths
{
    public const string DataDirectoryEnvironmentVariable = "WELES_DATA_DIR";

    private WelesPaths(string root, bool demoMode)
    {
        Root = Path.GetFullPath(root);
        DatabaseDirectory = Path.Combine(Root, "data");
        DatabaseFile = Path.Combine(DatabaseDirectory, demoMode ? "weles-demo.db" : "weles.db");
        LogsDirectory = Path.Combine(Root, "logs");
        ConfigDirectory = Path.Combine(Root, "config");
        ReportsDirectory = Path.Combine(Root, "reports");
        ExportsDirectory = Path.Combine(Root, "exports");
        VulnerabilityDataDirectory = Path.Combine(Root, "vulndb");
        KeysDirectory = Path.Combine(Root, "keys");
        InstanceFile = Path.Combine(Root, demoMode ? "instance-demo.json" : "instance.json");
    }

    public string Root { get; }
    public string DatabaseDirectory { get; }
    public string DatabaseFile { get; }
    public string LogsDirectory { get; }
    public string ConfigDirectory { get; }
    public string ReportsDirectory { get; }
    public string ExportsDirectory { get; }
    public string VulnerabilityDataDirectory { get; }
    public string KeysDirectory { get; }
    public string InstanceFile { get; }

    public IEnumerable<string> AllDirectories =>
        [Root, DatabaseDirectory, LogsDirectory, ConfigDirectory, ReportsDirectory, ExportsDirectory, VulnerabilityDataDirectory, KeysDirectory];

    /// <param name="overrideRoot">Explicit data directory (configuration or command line); takes precedence.</param>
    /// <param name="demoMode">Demo mode uses a separate database so demo data never mixes with real results.</param>
    public static WelesPaths Resolve(string? overrideRoot, bool demoMode = false)
    {
        var root = FirstNonEmpty(overrideRoot, Environment.GetEnvironmentVariable(DataDirectoryEnvironmentVariable))
                   ?? DefaultRoot();
        return new WelesPaths(root, demoMode);
    }

    public static string DefaultRoot()
    {
        // On Linux LocalApplicationData resolves to $XDG_DATA_HOME or ~/.local/share.
        var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify);
        if (string.IsNullOrWhiteSpace(baseDir))
        {
            baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        }

        return Path.Combine(baseDir, OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? "Weles" : "weles");
    }

    /// <summary>Creates all directories. On Unix the root is restricted to the current user (0700).</summary>
    public void EnsureCreated()
    {
        foreach (var dir in AllDirectories)
        {
            Directory.CreateDirectory(dir);
        }

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static string? FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
}
