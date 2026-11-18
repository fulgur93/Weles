using Microsoft.EntityFrameworkCore;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Tests.Support;

namespace Weles.Tests.Infrastructure;

public class DatabaseTests
{
    [Fact]
    public async Task Initializer_creates_database_applies_all_migrations_and_enables_wal()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        await using var db = testDb.CreateDbContext();

        Assert.True(File.Exists(testDb.FilePath));
        Assert.Empty(await db.Database.GetPendingMigrationsAsync());
        var mode = await db.Database.SqlQueryRaw<string>("PRAGMA journal_mode").ToListAsync();
        Assert.Equal("wal", mode.Single());
    }

    [Fact]
    public async Task Initializer_is_idempotent()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        await new Weles.Infrastructure.Database.DatabaseInitializer(testDb, Microsoft.Extensions.Logging.Abstractions.NullLogger<Weles.Infrastructure.Database.DatabaseInitializer>.Instance).InitializeAsync();
    }

    [Fact]
    public async Task Scan_snapshot_graph_round_trips_and_timestamps_are_utc()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        await using (var db = testDb.CreateDbContext())
        {
            var scan = TestData.CompletedScan(TestData.ApprovedTarget(), TestData.Now);
            scan.Hosts.Add(new DiscoveredHost
            {
                IpAddress = "192.168.1.10",
                DiscoveryMethods = DiscoveryMethod.Icmp | DiscoveryMethod.TcpConnect,
                DiscoveredAt = TestData.Now,
                Ports =
                [
                    new DiscoveredPort
                    {
                        Port = 22, Protocol = TransportProtocol.Tcp, State = PortState.Open, Reason = "syn-ack",
                        Service = new DiscoveredService { ServiceName = "ssh", Product = "OpenSSH", Version = "9.6p1", Confidence = 95, DetectionMethod = "banner" }
                    }
                ]
            });
            db.Scans.Add(scan);
            await db.SaveChangesAsync();
        }

        await using (var db = testDb.CreateDbContext())
        {
            var host = await db.DiscoveredHosts.Include(h => h.Ports).ThenInclude(p => p.Service).Include(h => h.Scan).SingleAsync();
            Assert.Equal(DiscoveryMethod.Icmp | DiscoveryMethod.TcpConnect, host.DiscoveryMethods);
            Assert.Equal("OpenSSH", host.Ports.Single().Service!.Product);
            Assert.Equal(DateTimeKind.Utc, host.Scan!.StartedAt!.Value.Kind);
            Assert.Equal(TestData.Now, host.DiscoveredAt);
        }
    }

    [Fact]
    public async Task Deleting_a_scan_cascades_to_its_snapshots_but_keeps_assets()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        await using (var db = testDb.CreateDbContext())
        {
            var asset = new Asset { DisplayName = "nas", FirstSeenAt = TestData.Now, LastSeenAt = TestData.Now };
            var scan = TestData.CompletedScan(TestData.ApprovedTarget(), TestData.Now);
            scan.Hosts.Add(new DiscoveredHost
            {
                IpAddress = "10.0.0.5", Asset = asset, DiscoveredAt = TestData.Now,
                Ports = [new DiscoveredPort { Port = 445, State = PortState.Open, Service = new DiscoveredService { ServiceName = "smb", Confidence = 40 } }]
            });
            db.Scans.Add(scan);
            await db.SaveChangesAsync();
        }

        await using (var db = testDb.CreateDbContext())
        {
            db.Scans.Remove(await db.Scans.SingleAsync());
            await db.SaveChangesAsync();

            Assert.Equal(0, await db.DiscoveredHosts.CountAsync());
            Assert.Equal(0, await db.DiscoveredPorts.CountAsync());
            Assert.Equal(0, await db.DiscoveredServices.CountAsync());
            Assert.Equal(1, await db.Assets.CountAsync());
        }
    }

    [Fact]
    public async Task Scan_target_with_scans_cannot_be_deleted()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        await using (var db = testDb.CreateDbContext())
        {
            db.Scans.Add(TestData.CompletedScan(TestData.ApprovedTarget(), TestData.Now));
            await db.SaveChangesAsync();
        }

        // Enforced by the database itself (FK ON DELETE RESTRICT), not only by the EF change tracker.
        await using (var db = testDb.CreateDbContext())
        {
            var ex = await Assert.ThrowsAsync<Microsoft.Data.Sqlite.SqliteException>(() => db.ScanTargets.ExecuteDeleteAsync());
            Assert.Contains("FOREIGN KEY", ex.Message);
            Assert.Equal(1, await db.ScanTargets.CountAsync());
        }
    }

    [Fact]
    public async Task Cve_id_is_unique()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        await using var db = testDb.CreateDbContext();
        db.Vulnerabilities.Add(new Vulnerability { CveId = "CVE-2024-6387", Source = "NVD" });
        db.Vulnerabilities.Add(new Vulnerability { CveId = "CVE-2024-6387", Source = "NVD" });

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    public async Task Port_outside_valid_range_is_rejected_by_check_constraint(int port)
    {
        await using var testDb = await TestDatabase.CreateAsync();
        await using var db = testDb.CreateDbContext();
        var scan = TestData.CompletedScan(TestData.ApprovedTarget(), TestData.Now);
        scan.Hosts.Add(new DiscoveredHost { IpAddress = "10.0.0.1", DiscoveredAt = TestData.Now, Ports = [new DiscoveredPort { Port = port }] });
        db.Scans.Add(scan);

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task Service_confidence_outside_0_100_is_rejected()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        await using var db = testDb.CreateDbContext();
        var scan = TestData.CompletedScan(TestData.ApprovedTarget(), TestData.Now);
        scan.Hosts.Add(new DiscoveredHost
        {
            IpAddress = "10.0.0.1", DiscoveredAt = TestData.Now,
            Ports = [new DiscoveredPort { Port = 80, Service = new DiscoveredService { Confidence = 150 } }]
        });
        db.Scans.Add(scan);

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task Same_ip_cannot_appear_twice_in_one_scan()
    {
        await using var testDb = await TestDatabase.CreateAsync();
        await using var db = testDb.CreateDbContext();
        var scan = TestData.CompletedScan(TestData.ApprovedTarget(), TestData.Now);
        scan.Hosts.Add(new DiscoveredHost { IpAddress = "10.0.0.1", DiscoveredAt = TestData.Now });
        scan.Hosts.Add(new DiscoveredHost { IpAddress = "10.0.0.1", DiscoveredAt = TestData.Now });
        db.Scans.Add(scan);

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }
}
