using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <inheritdoc />
    public partial class Stage8ExternalScopes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsExternal",
                table: "ScanTargets",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            // Scopes already prepared in the Attack Surface module are external.
            migrationBuilder.Sql("UPDATE ScanTargets SET IsExternal = 1 WHERE Id IN (SELECT ScanTargetId FROM ExternalTargets WHERE ScanTargetId IS NOT NULL);");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Plain DROP COLUMN (SQLite 3.35+) instead of EF's table rebuild, which would change the other columns' definitions.
            migrationBuilder.Sql("ALTER TABLE ScanTargets DROP COLUMN IsExternal;");
        }
    }
}
