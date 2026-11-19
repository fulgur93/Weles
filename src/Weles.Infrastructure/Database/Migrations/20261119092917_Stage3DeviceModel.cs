using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <inheritdoc />
    public partial class Stage3DeviceModel : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Model",
                table: "Assets",
                type: "TEXT",
                maxLength: 128,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Model",
                table: "Assets");
        }
    }
}
