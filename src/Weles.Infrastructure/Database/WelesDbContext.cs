using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Weles.Core.Entities;

namespace Weles.Infrastructure.Database;

public class WelesDbContext(DbContextOptions<WelesDbContext> options) : DbContext(options)
{
    public DbSet<ApplicationSetting> Settings => Set<ApplicationSetting>();
    public DbSet<ScanTarget> ScanTargets => Set<ScanTarget>();
    public DbSet<ScanTargetEntry> ScanTargetEntries => Set<ScanTargetEntry>();
    public DbSet<Scan> Scans => Set<Scan>();
    public DbSet<NetworkSegment> NetworkSegments => Set<NetworkSegment>();
    public DbSet<Asset> Assets => Set<Asset>();
    public DbSet<DiscoveredHost> DiscoveredHosts => Set<DiscoveredHost>();
    public DbSet<DiscoveredPort> DiscoveredPorts => Set<DiscoveredPort>();
    public DbSet<DiscoveredService> DiscoveredServices => Set<DiscoveredService>();
    public DbSet<Certificate> Certificates => Set<Certificate>();
    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();
    public DbSet<VulnerabilityAffectedProduct> VulnerabilityAffectedProducts => Set<VulnerabilityAffectedProduct>();
    public DbSet<AssetVulnerability> AssetVulnerabilities => Set<AssetVulnerability>();
    public DbSet<RiskFinding> RiskFindings => Set<RiskFinding>();
    public DbSet<RiskScore> RiskScores => Set<RiskScore>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(WelesDbContext).Assembly);
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        // SQLite has no native date type; all timestamps are stored and returned as UTC.
        configurationBuilder.Properties<DateTime>().HaveConversion<UtcDateTimeConverter>();
        configurationBuilder.Properties<DateTime?>().HaveConversion<NullableUtcDateTimeConverter>();
    }

    private sealed class UtcDateTimeConverter() : ValueConverter<DateTime, DateTime>(
        v => v.Kind == DateTimeKind.Utc ? v : v.ToUniversalTime(),
        v => DateTime.SpecifyKind(v, DateTimeKind.Utc));

    private sealed class NullableUtcDateTimeConverter() : ValueConverter<DateTime?, DateTime?>(
        v => v.HasValue ? (v.Value.Kind == DateTimeKind.Utc ? v : v.Value.ToUniversalTime()) : v,
        v => v.HasValue ? DateTime.SpecifyKind(v.Value, DateTimeKind.Utc) : v);
}
