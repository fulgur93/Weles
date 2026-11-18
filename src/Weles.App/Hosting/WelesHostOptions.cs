namespace Weles.App.Hosting;

public sealed class WelesHostOptions
{
    public const string SectionName = "Weles";

    /// <summary>Preferred port. If it is taken, a free port is assigned automatically.</summary>
    public int Port { get; set; } = 5080;

    public bool OpenBrowser { get; set; } = true;

    /// <summary>When another instance is already running, open its UI and exit.</summary>
    public bool SingleInstance { get; set; } = true;

    /// <summary>Require the launch token cookie for every request. Disable only for local development.</summary>
    public bool RequireAccessToken { get; set; } = true;

    public string? DataDirectory { get; set; }

    /// <summary>Clearly labelled demo mode with a separate database.</summary>
    public bool DemoMode { get; set; }
}
