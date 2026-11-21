using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <inheritdoc />
    public partial class Stage10Agents : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "AgentId",
                table: "Scans",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "Agents",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    EnrollmentCodeHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    EnrollmentExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    EnrolledAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    TokenHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    LastSeenAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastAddress = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    Hostname = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    OperatingSystem = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    AgentVersion = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    SystemInfoJson = table.Column<string>(type: "TEXT", maxLength: 64000, nullable: true),
                    RevokedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Agents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AgentScopes",
                columns: table => new
                {
                    AgentId = table.Column<int>(type: "INTEGER", nullable: false),
                    ScanTargetId = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AgentScopes", x => new { x.AgentId, x.ScanTargetId });
                    table.ForeignKey(
                        name: "FK_AgentScopes_Agents_AgentId",
                        column: x => x.AgentId,
                        principalTable: "Agents",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AgentScopes_ScanTargets_ScanTargetId",
                        column: x => x.ScanTargetId,
                        principalTable: "ScanTargets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Scans_AgentId",
                table: "Scans",
                column: "AgentId");

            migrationBuilder.CreateIndex(
                name: "IX_Agents_EnrollmentCodeHash",
                table: "Agents",
                column: "EnrollmentCodeHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Agents_Name",
                table: "Agents",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Agents_TokenHash",
                table: "Agents",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AgentScopes_ScanTargetId",
                table: "AgentScopes",
                column: "ScanTargetId");

            migrationBuilder.AddForeignKey(
                name: "FK_Scans_Agents_AgentId",
                table: "Scans",
                column: "AgentId",
                principalTable: "Agents",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Scans_Agents_AgentId",
                table: "Scans");

            migrationBuilder.DropTable(
                name: "AgentScopes");

            migrationBuilder.DropTable(
                name: "Agents");

            migrationBuilder.DropIndex(
                name: "IX_Scans_AgentId",
                table: "Scans");

            migrationBuilder.DropColumn(
                name: "AgentId",
                table: "Scans");
        }
    }
}
