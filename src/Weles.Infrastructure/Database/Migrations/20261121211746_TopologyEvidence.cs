using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <inheritdoc />
    public partial class TopologyEvidence : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "TracePath",
                table: "DiscoveredHosts",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "TracePath",
                table: "DiscoveredHosts");
        }
    }
}
