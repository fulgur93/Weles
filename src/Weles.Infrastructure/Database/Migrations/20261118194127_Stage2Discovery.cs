using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <inheritdoc />
    public partial class Stage2Discovery : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "UpdatedAt",
                table: "ScanTargets",
                type: "TEXT",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<int>(
                name: "HostsProbed",
                table: "Scans",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "HostsTargeted",
                table: "Scans",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "PortCount",
                table: "Scans",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "ScopeSnapshot",
                table: "Scans",
                type: "TEXT",
                maxLength: 8000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SettingsJson",
                table: "Scans",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "AssetTypeGuess",
                table: "DiscoveredHosts",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "ClassificationConfidence",
                table: "DiscoveredHosts",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "ClassificationReasons",
                table: "DiscoveredHosts",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsGateway",
                table: "DiscoveredHosts",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "ClassificationReasons",
                table: "Assets",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "ScanEvents",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ScanId = table.Column<int>(type: "INTEGER", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Level = table.Column<int>(type: "INTEGER", nullable: false),
                    Message = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanEvents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ScanEvents_Scans_ScanId",
                        column: x => x.ScanId,
                        principalTable: "Scans",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ScanEvents_ScanId_Timestamp",
                table: "ScanEvents",
                columns: new[] { "ScanId", "Timestamp" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ScanEvents");

            migrationBuilder.DropColumn(
                name: "UpdatedAt",
                table: "ScanTargets");

            migrationBuilder.DropColumn(
                name: "HostsProbed",
                table: "Scans");

            migrationBuilder.DropColumn(
                name: "HostsTargeted",
                table: "Scans");

            migrationBuilder.DropColumn(
                name: "PortCount",
                table: "Scans");

            migrationBuilder.DropColumn(
                name: "ScopeSnapshot",
                table: "Scans");

            migrationBuilder.DropColumn(
                name: "SettingsJson",
                table: "Scans");

            migrationBuilder.DropColumn(
                name: "AssetTypeGuess",
                table: "DiscoveredHosts");

            migrationBuilder.DropColumn(
                name: "ClassificationConfidence",
                table: "DiscoveredHosts");

            migrationBuilder.DropColumn(
                name: "ClassificationReasons",
                table: "DiscoveredHosts");

            migrationBuilder.DropColumn(
                name: "IsGateway",
                table: "DiscoveredHosts");

            migrationBuilder.DropColumn(
                name: "ClassificationReasons",
                table: "Assets");
        }
    }
}
