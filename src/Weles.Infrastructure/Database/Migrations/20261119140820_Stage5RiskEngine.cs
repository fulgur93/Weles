using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <inheritdoc />
    public partial class Stage5RiskEngine : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_RiskFindings_AssetId",
                table: "RiskFindings");

            migrationBuilder.AddColumn<string>(
                name: "AttackTechniques",
                table: "RiskFindings",
                type: "TEXT",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Confidence",
                table: "RiskFindings",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastDetectedAt",
                table: "RiskFindings",
                type: "TEXT",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<int>(
                name: "Port",
                table: "RiskFindings",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "ResolvedAt",
                table: "RiskFindings",
                type: "TEXT",
                nullable: true);

            migrationBuilder.Sql("UPDATE RiskFindings SET LastDetectedAt = CreatedAt;");

            migrationBuilder.CreateIndex(
                name: "IX_RiskFindings_AssetId_RuleId_Port",
                table: "RiskFindings",
                columns: new[] { "AssetId", "RuleId", "Port" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_RiskFindings_AssetId_RuleId_Port",
                table: "RiskFindings");

            migrationBuilder.DropColumn(
                name: "AttackTechniques",
                table: "RiskFindings");

            migrationBuilder.DropColumn(
                name: "Confidence",
                table: "RiskFindings");

            migrationBuilder.DropColumn(
                name: "LastDetectedAt",
                table: "RiskFindings");

            migrationBuilder.DropColumn(
                name: "Port",
                table: "RiskFindings");

            migrationBuilder.DropColumn(
                name: "ResolvedAt",
                table: "RiskFindings");

            migrationBuilder.CreateIndex(
                name: "IX_RiskFindings_AssetId",
                table: "RiskFindings",
                column: "AssetId");
        }
    }
}
