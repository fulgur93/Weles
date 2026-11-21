using System.Net;
using System.Net.Sockets;
using Weles.App.Hosting;
using Weles.Tests.Support;

namespace Weles.Tests.App;

public class HostingTests
{
    [Fact]
    public void Busy_preferred_port_falls_back_to_a_free_one()
    {
        using var occupant = new TcpListener(IPAddress.Loopback, 0);
        occupant.Start();
        var busy = ((IPEndPoint)occupant.LocalEndpoint).Port;

        var selected = PortSelector.SelectLoopbackPort(busy);

        Assert.NotEqual(busy, selected);
        Assert.True(PortSelector.IsAvailable(selected));
    }

    [Fact]
    public void Invalid_preferred_port_falls_back_to_a_free_one()
    {
        Assert.InRange(PortSelector.SelectLoopbackPort(0), 1, 65535);
        Assert.InRange(PortSelector.SelectLoopbackPort(70000), 1, 65535);
    }

    [Fact]
    public void Access_token_is_random_and_compared_exactly()
    {
        var a = new LocalAccessToken();
        var b = new LocalAccessToken();

        Assert.NotEqual(a.Value, b.Value);
        Assert.True(a.Value.Length >= 43, "256-bit token expected");
        Assert.True(a.Matches(a.Value));
        Assert.False(a.Matches(b.Value));
        Assert.False(a.Matches(null));
        Assert.False(a.Matches(""));
        Assert.False(a.Matches(a.Value[..^1]));
    }

    [Theory]
    [InlineData(new[] { "--demo" }, new[] { "--Weles:DemoMode=true" })]
    [InlineData(new[] { "--no-browser", "--port", "5090" }, new[] { "--Weles:OpenBrowser=false", "--Weles:Port=5090" })]
    [InlineData(new[] { "--data-dir", "/x y" }, new[] { "--Weles:DataDirectory=/x y" })]
    [InlineData(new[] { "--Weles:Port=1" }, new[] { "--Weles:Port=1" })]
    public void Command_line_switches_are_mapped_to_configuration(string[] input, string[] expected)
    {
        Assert.Equal(expected, CommandLine.Normalize(input));
    }

    [Fact]
    public void Instance_file_round_trips_is_private_and_stale_entries_are_ignored()
    {
        var dir = TempDirectory.Create();
        var file = Path.Combine(dir, "instance.json");

        // Our own PID is never treated as "another running instance".
        InstanceRegistry.Write(file, new InstanceInfo(Environment.ProcessId, 5080, "secret", DateTime.UtcNow));
        Assert.False(InstanceRegistry.TryGetRunningInstance(file, out _));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
        }

        InstanceRegistry.Remove(file);
        Assert.False(File.Exists(file));

        // Dead PID → stale.
        InstanceRegistry.Write(file, new InstanceInfo(int.MaxValue - 1, 5080, "secret", DateTime.UtcNow));
        Assert.False(InstanceRegistry.TryGetRunningInstance(file, out _));
        TempDirectory.Delete(dir);
    }

    [Fact]
    public void Launch_url_targets_loopback_auth_endpoint()
    {
        var info = new InstanceInfo(1, 5080, "a/b+c", DateTime.UtcNow);
        Assert.Equal("http://127.0.0.1:5080/auth?token=a%2Fb%2Bc", info.LaunchUrl);
    }

    [Fact]
    public void Autostart_writes_and_removes_the_login_entry()
    {
        if (!OperatingSystem.IsLinux()) return; // the Windows variant writes HKCU\...\Run – covered by the installer test on Windows
        var dir = TempDirectory.Create();
        try
        {
            var options = Microsoft.Extensions.Options.Options.Create(new WelesHostOptions { DataDirectory = "/data/weles dane" });
            var autostart = new Autostart(options, new RuntimeInfo(5080, false, TimeProvider.System), Microsoft.Extensions.Logging.Abstractions.NullLogger<Autostart>.Instance, dir);
            Assert.True(autostart.IsSupported);
            Assert.False(autostart.IsEnabled());

            autostart.Set(true);
            Assert.True(autostart.IsEnabled());
            var entry = File.ReadAllText(Path.Combine(dir, Autostart.DesktopFileName));
            Assert.Contains($"Exec=\"{Environment.ProcessPath}\" --no-browser --data-dir \"/data/weles dane\"", entry);
            Assert.StartsWith("[Desktop Entry]", entry);

            autostart.Set(false);
            Assert.False(autostart.IsEnabled());

            // The demo instance never starts at login.
            Assert.False(new Autostart(options, new RuntimeInfo(5080, true, TimeProvider.System), Microsoft.Extensions.Logging.Abstractions.NullLogger<Autostart>.Instance, dir).IsSupported);
        }
        finally
        {
            TempDirectory.Delete(dir);
        }
    }
}
