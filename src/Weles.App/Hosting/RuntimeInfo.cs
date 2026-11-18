using System.Reflection;

namespace Weles.App.Hosting;

/// <summary>Facts about the running instance shown in the UI.</summary>
public sealed class RuntimeInfo(int port, bool demoMode, TimeProvider timeProvider)
{
    public string Version { get; } = typeof(RuntimeInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";
    public int Port { get; } = port;
    public string BaseUrl => $"http://127.0.0.1:{Port}";
    public bool DemoMode { get; } = demoMode;
    public DateTime StartedAt { get; } = timeProvider.GetUtcNow().UtcDateTime;
    public string Framework { get; } = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;
    public string OperatingSystem { get; } = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
    public string Architecture { get; } = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString();
}
