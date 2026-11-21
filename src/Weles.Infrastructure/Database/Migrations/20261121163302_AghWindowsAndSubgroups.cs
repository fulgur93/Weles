using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <inheritdoc />
    public partial class AghWindowsAndSubgroups : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "WindowEndMinute",
                table: "ScanSchedules",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "WindowStartMinute",
                table: "ScanSchedules",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "CompletedAddresses",
                table: "Scans",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "WindowEndMinute",
                table: "ScanSchedules");

            migrationBuilder.DropColumn(
                name: "WindowStartMinute",
                table: "ScanSchedules");

            migrationBuilder.DropColumn(
                name: "CompletedAddresses",
                table: "Scans");
        }
    }
}
