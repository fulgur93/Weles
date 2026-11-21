using System;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <summary>
    /// Web observations, technologies and custom signatures – first version, already applied (2026-11-21) to databases of
    /// the development build. Kept with its original id, so those databases continue with <see cref="AghCweAndUsers"/>.
    /// </summary>
    [DbContext(typeof(WelesDbContext))]
    [Migration("20261121113123_WebFingerprint")]
    public partial class WebFingerprint : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "WebJson",
                table: "DiscoveredServices",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "CustomSignatures",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SignatureId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Json = table.Column<string>(type: "TEXT", maxLength: 20000, nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedBy = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CustomSignatures", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ServiceTechnologies",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DiscoveredServiceId = table.Column<int>(type: "INTEGER", nullable: false),
                    SignatureId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Category = table.Column<int>(type: "INTEGER", nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 40, nullable: true),
                    Confidence = table.Column<int>(type: "INTEGER", nullable: false),
                    Evidence = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ServiceTechnologies", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ServiceTechnologies_DiscoveredServices_DiscoveredServiceId",
                        column: x => x.DiscoveredServiceId,
                        principalTable: "DiscoveredServices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CustomSignatures_SignatureId",
                table: "CustomSignatures",
                column: "SignatureId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ServiceTechnologies_DiscoveredServiceId",
                table: "ServiceTechnologies",
                column: "DiscoveredServiceId");

            migrationBuilder.CreateIndex(
                name: "IX_ServiceTechnologies_Name",
                table: "ServiceTechnologies",
                column: "Name");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CustomSignatures");

            migrationBuilder.DropTable(
                name: "ServiceTechnologies");

            migrationBuilder.Sql("ALTER TABLE DiscoveredServices DROP COLUMN WebJson;");
        }
    }
}
