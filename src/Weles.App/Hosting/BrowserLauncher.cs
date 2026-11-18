using System.Diagnostics;

namespace Weles.App.Hosting;

public static class BrowserLauncher
{
    /// <summary>Opens the URL in the default browser. The URL is generated internally – never from user input.</summary>
    public static bool TryOpen(string url, ILogger logger)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp || !uri.IsLoopback)
        {
            logger.LogError("Refusing to open a non-loopback URL in the browser");
            return false;
        }

        try
        {
            ProcessStartInfo psi;
            if (OperatingSystem.IsWindows())
            {
                psi = new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true };
            }
            else if (OperatingSystem.IsMacOS())
            {
                psi = new ProcessStartInfo("open") { ArgumentList = { uri.AbsoluteUri } };
            }
            else
            {
                psi = new ProcessStartInfo("xdg-open") { ArgumentList = { uri.AbsoluteUri } };
            }

            psi.RedirectStandardError = !psi.UseShellExecute;
            psi.RedirectStandardOutput = !psi.UseShellExecute;
            using var _ = Process.Start(psi);
            return true;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or PlatformNotSupportedException)
        {
            logger.LogWarning("Could not open the browser automatically: {Message}", ex.Message);
            return false;
        }
    }
}
