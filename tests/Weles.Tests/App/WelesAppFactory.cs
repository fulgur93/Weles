using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Weles.Tests.Support;

namespace Weles.Tests.App;

public sealed class WelesAppFactory : WebApplicationFactory<Program>
{
    public string DataDirectory { get; } = TempDirectory.Create();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseContentRoot(AppContext.BaseDirectory);
        builder.UseSetting("Weles:DataDirectory", DataDirectory);
        builder.UseSetting("Weles:OpenBrowser", "false");
        builder.UseSetting("Weles:SingleInstance", "false");
        builder.UseSetting("Weles:Ai:Endpoint", "http://127.0.0.1:9"); // nothing listens – AI must degrade gracefully
        builder.UseSetting("Weles:Ai:StatusTimeoutSeconds", "1");
        builder.UseSetting("Weles:Ai:ManageEngine", "false"); // tests never start the bundled engine
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        TempDirectory.Delete(DataDirectory);
    }
}
