using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Weles.Core.Entities;

namespace Weles.Infrastructure.Database.Configurations;

internal sealed class AuditReportConfiguration : IEntityTypeConfiguration<AuditReport>
{
    public void Configure(EntityTypeBuilder<AuditReport> b)
    {
        b.Property(x => x.FileName).HasMaxLength(200);
        b.Property(x => x.Sha256).HasMaxLength(64);
        b.Property(x => x.Language).HasMaxLength(5);
        b.HasIndex(x => x.CreatedAt);
        // The file stays on disk when its audit is removed with the scan; the record goes with it.
        b.HasOne(x => x.Scan).WithMany().HasForeignKey(x => x.ScanId).OnDelete(DeleteBehavior.Cascade);
        b.HasOne(x => x.ImportedAudit).WithMany().HasForeignKey(x => x.ImportedAuditId).OnDelete(DeleteBehavior.Cascade);
        b.ToTable(t => t.HasCheckConstraint("CK_AuditReports_Source", "(ScanId IS NULL) <> (ImportedAuditId IS NULL)"));
    }
}

internal sealed class AuditAiSummaryConfiguration : IEntityTypeConfiguration<AuditAiSummary>
{
    public void Configure(EntityTypeBuilder<AuditAiSummary> b)
    {
        b.Property(x => x.Text).HasMaxLength(20_000);
        b.Property(x => x.Model).HasMaxLength(200);
        b.Property(x => x.Language).HasMaxLength(5);
        // One summary per audit – generating again replaces it.
        b.HasIndex(x => x.ScanId).IsUnique();
        b.HasOne(x => x.Scan).WithMany().HasForeignKey(x => x.ScanId).OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class ImportedAuditConfiguration : IEntityTypeConfiguration<ImportedAudit>
{
    public void Configure(EntityTypeBuilder<ImportedAudit> b)
    {
        b.Property(x => x.Title).HasMaxLength(300);
        b.Property(x => x.ExportedBy).HasMaxLength(100);
        b.Property(x => x.SourceFileName).HasMaxLength(260);
        b.Property(x => x.Sha256).HasMaxLength(64);
        b.HasIndex(x => x.Sha256).IsUnique();
    }
}
