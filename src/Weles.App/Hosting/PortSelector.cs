using System.Net;
using System.Net.Sockets;

namespace Weles.App.Hosting;

public static class PortSelector
{
    /// <summary>Returns <paramref name="preferredPort"/> if it can be bound on loopback, otherwise a free ephemeral port.</summary>
    public static int SelectLoopbackPort(int preferredPort)
    {
        if (preferredPort is > 0 and <= IPEndPoint.MaxPort && IsAvailable(preferredPort))
        {
            return preferredPort;
        }

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    public static bool IsAvailable(int port)
    {
        try
        {
            using var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Server.ExclusiveAddressUse = OperatingSystem.IsWindows();
            listener.Start();
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
