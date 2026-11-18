using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Weles.Core.Entities;

namespace Weles.Infrastructure.Database.Configurations;

internal sealed class ApplicationSettingConfiguration : IEntityTypeConfiguration<ApplicationSetting>
{
    public void Configure(EntityTypeBuilder<ApplicationSetting> b)
    {
        b.HasKey(x => x.Key);
        b.Property(x => x.Key).HasMaxLength(128);
        b.Property(x => x.Value).HasMaxLength(4000);
    }
}

internal sealed class ScanTargetConfiguration : IEntityTypeConfiguration<ScanTarget>
{
    public void Configure(EntityTypeBuilder<ScanTarget> b)
    {
        b.Property(x => x.Name).HasMaxLength(200);
        b.Property(x => x.Description).HasMaxLength(2000);
        b.HasIndex(x => x.Name);
        b.HasMany(x => x.Entries).WithOne(x => x.ScanTarget).HasForeignKey(x => x.ScanTargetId).OnDelete(DeleteBehavior.Cascade);
        // A scope that already has scans cannot be deleted – audit history must be preserved.
        b.HasMany(x => x.Scans).WithOne(x => x.ScanTarget).HasForeignKey(x => x.ScanTargetId).OnDelete(DeleteBehavior.Restrict);
    }
}

internal sealed class ScanTargetEntryConfiguration : IEntityTypeConfiguration<ScanTargetEntry>
{
    public void Configure(EntityTypeBuilder<ScanTargetEntry> b)
    {
        b.Property(x => x.Value).HasMaxLength(255);
        b.HasIndex(x => new { x.ScanTargetId, x.Value, x.IsExclusion }).IsUnique();
    }
}

internal sealed class ScanConfiguration : IEntityTypeConfiguration<Scan>
{
    public void Configure(EntityTypeBuilder<Scan> b)
    {
        b.Property(x => x.PortSpecification).HasMaxLength(1000);
        b.Property(x => x.ErrorMessage).HasMaxLength(2000);
        b.HasIndex(x => new { x.Status, x.StartedAt });
        b.HasIndex(x => x.CreatedAt);
        b.HasMany(x => x.Hosts).WithOne(x => x.Scan).HasForeignKey(x => x.ScanId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(x => x.Findings).WithOne(x => x.Scan).HasForeignKey(x => x.ScanId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(x => x.RiskScores).WithOne(x => x.Scan).HasForeignKey(x => x.ScanId).OnDelete(DeleteBehavior.Cascade);
        b.ToTable(t => t.HasCheckConstraint("CK_Scan_Counters", "HostsAlive >= 0 AND OpenPorts >= 0"));
    }
}
