using System.Reflection;
using System.Runtime.InteropServices;
using Weles.Infrastructure.Agents;
using Weles.Infrastructure.Discovery;

namespace Weles.Agent.Scanning;

/// <summary>
/// The "selected system information" an agent reports: host name, OS, architecture, CPU count, agent version and the
/// network interfaces (address, prefix, gateway, MAC) – so WELES knows which segments the agent can reach. Nothing else
/// (no users, processes, files).
/// </summary>
public static class SystemInfoCollector
{
    public static string Version { get; } =
        typeof(SystemInfoCollector).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    public static AgentSystemInfo Collect(LocalNetworkDiscovery network) => new(
        Environment.MachineName,
        RuntimeInformation.OSDescription,
        RuntimeInformation.OSArchitecture.ToString(),
        Version,
        Environment.ProcessorCount,
        network.GetInterfaces().Select(i => new AgentInterface(i.Name, i.Type, i.Address, i.PrefixLength, i.NetworkCidr, i.Gateway, i.MacAddress)).ToList());
}
