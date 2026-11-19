using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <inheritdoc />
    public partial class Stage3NetworkSegments : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_NetworkSegments_Cidr",
                table: "NetworkSegments");

            migrationBuilder.AddColumn<string>(
                name: "GatewayMac",
                table: "NetworkSegments",
                type: "TEXT",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "GatewayVendor",
                table: "NetworkSegments",
                type: "TEXT",
                maxLength: 255,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_NetworkSegments_Cidr_GatewayMac",
                table: "NetworkSegments",
                columns: new[] { "Cidr", "GatewayMac" },
                unique: true);

            // Split segments that mixed several networks with the same CIDR: every asset moves to the segment of the
            // network (gateway fingerprint) of its latest observation; segments left empty and superseded are removed.
            migrationBuilder.Sql("""
                CREATE TEMP TABLE _asset_net AS
                SELECT a.Id AS AssetId, s.Cidr AS Cidr, s.Gateway AS Gateway, a.FirstSeenAt AS FirstSeenAt, a.LastSeenAt AS LastSeenAt,
                       (SELECT sc.NetworkFingerprint FROM DiscoveredHosts h JOIN Scans sc ON sc.Id = h.ScanId
                        WHERE h.AssetId = a.Id ORDER BY h.DiscoveredAt DESC LIMIT 1) AS Fp
                FROM Assets a JOIN NetworkSegments s ON s.Id = a.NetworkSegmentId;

                INSERT INTO NetworkSegments (Cidr, Gateway, GatewayMac, GatewayVendor, FirstSeenAt, LastSeenAt)
                SELECT t.Cidr, MIN(t.Gateway), t.Fp,
                       (SELECT h.Vendor FROM DiscoveredHosts h WHERE h.IsGateway = 1 AND lower(h.MacAddress) = t.Fp AND h.Vendor IS NOT NULL LIMIT 1),
                       MIN(t.FirstSeenAt), MAX(t.LastSeenAt)
                FROM _asset_net t WHERE t.Fp IS NOT NULL GROUP BY t.Cidr, t.Fp;

                UPDATE Assets SET NetworkSegmentId = (
                    SELECT n.Id FROM NetworkSegments n JOIN _asset_net t ON t.Cidr = n.Cidr AND t.Fp = n.GatewayMac WHERE t.AssetId = Assets.Id)
                WHERE Id IN (SELECT AssetId FROM _asset_net WHERE Fp IS NOT NULL);

                DELETE FROM NetworkSegments
                WHERE GatewayMac IS NULL
                  AND Id NOT IN (SELECT NetworkSegmentId FROM Assets WHERE NetworkSegmentId IS NOT NULL)
                  AND Cidr IN (SELECT Cidr FROM NetworkSegments WHERE GatewayMac IS NOT NULL);

                DROP TABLE _asset_net;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_NetworkSegments_Cidr_GatewayMac",
                table: "NetworkSegments");

            migrationBuilder.DropColumn(
                name: "GatewayMac",
                table: "NetworkSegments");

            migrationBuilder.DropColumn(
                name: "GatewayVendor",
                table: "NetworkSegments");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkSegments_Cidr",
                table: "NetworkSegments",
                column: "Cidr",
                unique: true);
        }
    }
}
