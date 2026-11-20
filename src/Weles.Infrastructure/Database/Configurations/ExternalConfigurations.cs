using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Weles.Core.Entities;

namespace Weles.Infrastructure.Database.Configurations;

internal sealed class ExternalTargetConfiguration : IEntityTypeConfiguration<ExternalTarget>
{
    public void Configure(EntityTypeBuilder<ExternalTarget> b)
    {
        b.Property(x => x.Name).HasMaxLength(253);
        b.Property(x => x.Description).HasMaxLength(1000);
        b.Property(x => x.KnownHosts).HasMaxLength(20_000);
        b.HasIndex(x => x.Name).IsUnique();
        // Deleting a target keeps the scope and its scan history – audits must stay intact.
        b.HasOne(x => x.ScanTarget).WithMany().HasForeignKey(x => x.ScanTargetId).OnDelete(DeleteBehavior.SetNull);
        b.HasMany(x => x.Analyses).WithOne(x => x.ExternalTarget).HasForeignKey(x => x.ExternalTargetId).OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class ExternalAnalysisConfiguration : IEntityTypeConfiguration<ExternalAnalysis>
{
    public void Configure(EntityTypeBuilder<ExternalAnalysis> b)
    {
        b.Property(x => x.Error).HasMaxLength(2000);
        b.HasIndex(x => new { x.ExternalTargetId, x.StartedAt });
    }
}
