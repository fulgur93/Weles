using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Weles.Core.Entities;

namespace Weles.Infrastructure.Database.Configurations;

internal sealed class ServiceTechnologyConfiguration : IEntityTypeConfiguration<ServiceTechnology>
{
    public void Configure(EntityTypeBuilder<ServiceTechnology> b)
    {
        b.Property(x => x.SignatureId).HasMaxLength(64);
        b.Property(x => x.Name).HasMaxLength(100);
        b.Property(x => x.Version).HasMaxLength(40);
        b.Property(x => x.Evidence).HasMaxLength(4000);
        b.HasIndex(x => x.Name);
        b.HasOne(x => x.Service).WithMany(x => x.Technologies).HasForeignKey(x => x.DiscoveredServiceId).OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class CustomSignatureConfiguration : IEntityTypeConfiguration<CustomSignature>
{
    public void Configure(EntityTypeBuilder<CustomSignature> b)
    {
        b.Property(x => x.SignatureId).HasMaxLength(64);
        b.HasIndex(x => x.SignatureId).IsUnique();
        b.Property(x => x.Json).HasMaxLength(20_000);
        b.Property(x => x.UpdatedBy).HasMaxLength(100);
    }
}

internal sealed class AppUserConfiguration : IEntityTypeConfiguration<AppUser>
{
    public void Configure(EntityTypeBuilder<AppUser> b)
    {
        b.Property(x => x.UserName).HasMaxLength(50);
        b.HasIndex(x => x.UserName).IsUnique();
        b.Property(x => x.PasswordHash).HasMaxLength(200);
        b.Property(x => x.SecurityStamp).HasMaxLength(64);
    }
}
