using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Weles.Core.Entities;

namespace Weles.Infrastructure.Database.Configurations;

internal sealed class AiConversationConfiguration : IEntityTypeConfiguration<AiConversation>
{
    public void Configure(EntityTypeBuilder<AiConversation> b)
    {
        b.Property(x => x.Title).HasMaxLength(200);
        b.Property(x => x.Language).HasMaxLength(8);
        b.Property(x => x.Model).HasMaxLength(200);
        b.HasIndex(x => x.UpdatedAt);
        b.HasMany(x => x.Messages).WithOne(x => x.Conversation).HasForeignKey(x => x.ConversationId).OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class AiMessageConfiguration : IEntityTypeConfiguration<AiMessage>
{
    public void Configure(EntityTypeBuilder<AiMessage> b)
    {
        b.Property(x => x.Role).HasMaxLength(16);
        b.Property(x => x.Content).HasMaxLength(64_000);
        b.Property(x => x.ContextSources).HasMaxLength(4000);
        b.Property(x => x.Error).HasMaxLength(2000);
        b.HasIndex(x => new { x.ConversationId, x.CreatedAt });
    }
}

internal sealed class ScanScheduleConfiguration : IEntityTypeConfiguration<ScanSchedule>
{
    public void Configure(EntityTypeBuilder<ScanSchedule> b)
    {
        b.Property(x => x.PortSpecification).HasMaxLength(2000);
        b.Property(x => x.NetworkFingerprint).HasMaxLength(200);
        b.Property(x => x.LastResult).HasMaxLength(500);
        b.HasIndex(x => x.ScanTargetId).IsUnique();
        b.HasIndex(x => new { x.IsEnabled, x.NextRunAt });
        b.HasOne(x => x.ScanTarget).WithMany().HasForeignKey(x => x.ScanTargetId).OnDelete(DeleteBehavior.Cascade);
    }
}
