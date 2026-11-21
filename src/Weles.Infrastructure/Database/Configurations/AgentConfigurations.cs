using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Weles.Core.Entities;

namespace Weles.Infrastructure.Database.Configurations;

internal sealed class AgentConfiguration : IEntityTypeConfiguration<Agent>
{
    public void Configure(EntityTypeBuilder<Agent> b)
    {
        b.Property(x => x.Name).HasMaxLength(100);
        b.HasIndex(x => x.Name).IsUnique();
        b.Property(x => x.EnrollmentCodeHash).HasMaxLength(64);
        b.Property(x => x.TokenHash).HasMaxLength(64);
        b.HasIndex(x => x.TokenHash).IsUnique();
        b.HasIndex(x => x.EnrollmentCodeHash).IsUnique();
        b.Property(x => x.LastAddress).HasMaxLength(64);
        b.Property(x => x.Hostname).HasMaxLength(255);
        b.Property(x => x.OperatingSystem).HasMaxLength(200);
        b.Property(x => x.AgentVersion).HasMaxLength(50);
        b.Property(x => x.SystemInfoJson).HasMaxLength(64_000);
        b.HasMany(x => x.Scopes).WithOne(x => x.Agent).HasForeignKey(x => x.AgentId).OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class AgentScopeConfiguration : IEntityTypeConfiguration<AgentScope>
{
    public void Configure(EntityTypeBuilder<AgentScope> b)
    {
        b.HasKey(x => new { x.AgentId, x.ScanTargetId });
        b.HasOne(x => x.ScanTarget).WithMany().HasForeignKey(x => x.ScanTargetId).OnDelete(DeleteBehavior.Cascade);
    }
}
