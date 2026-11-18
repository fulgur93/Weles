using Weles.Infrastructure.Platform;
using Weles.Tests.Support;

namespace Weles.Tests.Infrastructure;

public class WelesPathsTests
{
    [Fact]
    public void Override_root_takes_precedence_and_all_paths_are_inside_it()
    {
        var root = TempDirectory.Create();
        var paths = WelesPaths.Resolve(root);

        Assert.Equal(Path.GetFullPath(root), paths.Root);
        Assert.All(paths.AllDirectories, d => Assert.StartsWith(paths.Root, d));
        Assert.StartsWith(paths.Root, paths.DatabaseFile);
        Assert.EndsWith("weles.db", paths.DatabaseFile);
        TempDirectory.Delete(root);
    }

    [Fact]
    public void Demo_mode_uses_a_separate_database_and_instance_file()
    {
        var root = TempDirectory.Create();
        var normal = WelesPaths.Resolve(root);
        var demo = WelesPaths.Resolve(root, demoMode: true);

        Assert.NotEqual(normal.DatabaseFile, demo.DatabaseFile);
        Assert.NotEqual(normal.InstanceFile, demo.InstanceFile);
        TempDirectory.Delete(root);
    }

    [Fact]
    public void EnsureCreated_creates_every_directory_with_private_permissions()
    {
        var root = Path.Combine(TempDirectory.Create(), "nested", "weles");
        var paths = WelesPaths.Resolve(root);

        paths.EnsureCreated();

        Assert.All(paths.AllDirectories, d => Assert.True(Directory.Exists(d), d));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(paths.Root));
        }
    }

    [Fact]
    public void Default_root_is_never_the_installation_directory()
    {
        Assert.False(WelesPaths.DefaultRoot().StartsWith(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase));
    }
}
