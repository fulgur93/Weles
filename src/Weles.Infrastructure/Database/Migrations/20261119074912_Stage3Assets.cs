using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <inheritdoc />
    public partial class Stage3Assets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CustomName",
                table: "Assets",
                type: "TEXT",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "UserAssetType",
                table: "Assets",
                type: "INTEGER",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CustomName",
                table: "Assets");

            migrationBuilder.DropColumn(
                name: "UserAssetType",
                table: "Assets");
        }
    }
}
