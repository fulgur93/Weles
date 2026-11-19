using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <inheritdoc />
    public partial class Stage3NetworkIdentity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "NetworkFingerprint",
                table: "Scans",
                type: "TEXT",
                maxLength: 200,
                nullable: true);

            // Scans made before this migration: the gateway observed in the scan identifies its network.
            migrationBuilder.Sql("""
                UPDATE Scans SET NetworkFingerprint = (
                    SELECT group_concat(m, ',') FROM (
                        SELECT DISTINCT lower(MacAddress) AS m FROM DiscoveredHosts
                        WHERE DiscoveredHosts.ScanId = Scans.Id AND IsGateway = 1 AND MacAddress IS NOT NULL
                        ORDER BY m));
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "NetworkFingerprint",
                table: "Scans");
        }
    }
}
