using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Weles.Core.Entities;

namespace Weles.Infrastructure.Database.Configurations;

internal sealed class NetworkSegmentConfiguration : IEntityTypeConfiguration<NetworkSegment>
{
    public void Configure(EntityTypeBuilder<NetworkSegment> b)
    {
        b.Property(x => x.Cidr).HasMaxLength(64);
        b.Property(x => x.Name).HasMaxLength(200);
        b.Property(x => x.Gateway).HasMaxLength(64);
        b.HasIndex(x => x.Cidr).IsUnique();
        b.HasMany(x => x.Assets).WithOne(x => x.NetworkSegment).HasForeignKey(x => x.NetworkSegmentId).OnDelete(DeleteBehavior.SetNull);
    }
}

internal sealed class AssetConfiguration : IEntityTypeConfiguration<Asset>
{
    public void Configure(EntityTypeBuilder<Asset> b)
    {
        b.Property(x => x.DisplayName).HasMaxLength(255);
        b.Property(x => x.Hostname).HasMaxLength(255);
        b.Property(x => x.PrimaryIpAddress).HasMaxLength(64);
        b.Property(x => x.MacAddress).HasMaxLength(17);
        b.Property(x => x.Vendor).HasMaxLength(255);
        b.Property(x => x.OsFamily).HasMaxLength(100);
        b.Property(x => x.OsDetails).HasMaxLength(500);
        b.Property(x => x.Notes).HasMaxLength(4000);
        b.HasIndex(x => x.MacAddress);
        b.HasIndex(x => x.PrimaryIpAddress);
        b.HasIndex(x => x.LastSeenAt);
        b.HasIndex(x => x.CurrentRiskLevel);
        b.HasMany(x => x.Observations).WithOne(x => x.Asset).HasForeignKey(x => x.AssetId).OnDelete(DeleteBehavior.SetNull);
        b.HasMany(x => x.Vulnerabilities).WithOne(x => x.Asset).HasForeignKey(x => x.AssetId).OnDelete(DeleteBehavior.Cascade);
        b.ToTable(t => t.HasCheckConstraint("CK_Asset_RiskScore", "CurrentRiskScore IS NULL OR (CurrentRiskScore >= 0 AND CurrentRiskScore <= 100)"));
    }
}

internal sealed class DiscoveredHostConfiguration : IEntityTypeConfiguration<DiscoveredHost>
{
    public void Configure(EntityTypeBuilder<DiscoveredHost> b)
    {
        b.Property(x => x.IpAddress).HasMaxLength(64);
        b.Property(x => x.Hostname).HasMaxLength(255);
        b.Property(x => x.MacAddress).HasMaxLength(17);
        b.Property(x => x.Vendor).HasMaxLength(255);
        b.Property(x => x.OsGuess).HasMaxLength(255);
        b.HasIndex(x => new { x.ScanId, x.IpAddress }).IsUnique();
        b.HasIndex(x => x.AssetId);
        b.HasMany(x => x.Ports).WithOne(x => x.Host).HasForeignKey(x => x.DiscoveredHostId).OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class DiscoveredPortConfiguration : IEntityTypeConfiguration<DiscoveredPort>
{
    public void Configure(EntityTypeBuilder<DiscoveredPort> b)
    {
        b.Property(x => x.Reason).HasMaxLength(64);
        b.HasIndex(x => new { x.DiscoveredHostId, x.Port, x.Protocol }).IsUnique();
        b.HasOne(x => x.Service).WithOne(x => x.Port).HasForeignKey<DiscoveredService>(x => x.DiscoveredPortId).OnDelete(DeleteBehavior.Cascade);
        b.ToTable(t => t.HasCheckConstraint("CK_DiscoveredPort_Port", "Port BETWEEN 1 AND 65535"));
    }
}

internal sealed class DiscoveredServiceConfiguration : IEntityTypeConfiguration<DiscoveredService>
{
    public void Configure(EntityTypeBuilder<DiscoveredService> b)
    {
        b.Property(x => x.ServiceName).HasMaxLength(100);
        b.Property(x => x.Product).HasMaxLength(255);
        b.Property(x => x.Vendor).HasMaxLength(255);
        b.Property(x => x.Version).HasMaxLength(100);
        b.Property(x => x.Cpe).HasMaxLength(500);
        b.Property(x => x.Banner).HasMaxLength(1024);
        b.Property(x => x.DetectionMethod).HasMaxLength(100);
        b.HasIndex(x => new { x.Product, x.Version });
        b.HasMany(x => x.Certificates).WithOne(x => x.Service).HasForeignKey(x => x.DiscoveredServiceId).OnDelete(DeleteBehavior.Cascade);
        b.ToTable(t => t.HasCheckConstraint("CK_DiscoveredService_Confidence", "Confidence BETWEEN 0 AND 100"));
    }
}

internal sealed class CertificateConfiguration : IEntityTypeConfiguration<Certificate>
{
    public void Configure(EntityTypeBuilder<Certificate> b)
    {
        b.Property(x => x.Subject).HasMaxLength(1000);
        b.Property(x => x.Issuer).HasMaxLength(1000);
        b.Property(x => x.Thumbprint).HasMaxLength(128);
        b.Property(x => x.SerialNumber).HasMaxLength(128);
        b.Property(x => x.SubjectAlternativeNames).HasMaxLength(4000);
        b.Property(x => x.KeyAlgorithm).HasMaxLength(64);
        b.Property(x => x.SignatureAlgorithm).HasMaxLength(128);
        b.Property(x => x.TlsProtocol).HasMaxLength(32);
        b.HasIndex(x => x.Thumbprint);
        b.HasIndex(x => x.NotAfter);
    }
}
