using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Weles.Infrastructure.Database;

/// <summary>Used only by the dotnet-ef tooling to create migrations.</summary>
internal sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<WelesDbContext>
{
    public WelesDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<WelesDbContext>()
            .UseSqlite("Data Source=design-time.db")
            .Options;
        return new WelesDbContext(options);
    }
}
