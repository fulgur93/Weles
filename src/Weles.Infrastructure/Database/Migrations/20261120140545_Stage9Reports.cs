using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <inheritdoc />
    public partial class Stage9Reports : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AuditAiSummaries",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ScanId = table.Column<int>(type: "INTEGER", nullable: false),
                    Text = table.Column<string>(type: "TEXT", maxLength: 20000, nullable: false),
                    Model = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Language = table.Column<string>(type: "TEXT", maxLength: 5, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditAiSummaries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AuditAiSummaries_Scans_ScanId",
                        column: x => x.ScanId,
                        principalTable: "Scans",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ImportedAudits",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Title = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                    OriginalScanId = table.Column<int>(type: "INTEGER", nullable: false),
                    AuditStartedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExportedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExportedBy = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    SchemaVersion = table.Column<int>(type: "INTEGER", nullable: false),
                    DeviceCount = table.Column<int>(type: "INTEGER", nullable: false),
                    PostureScore = table.Column<double>(type: "REAL", nullable: true),
                    SourceFileName = table.Column<string>(type: "TEXT", maxLength: 260, nullable: false),
                    Sha256 = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ImportedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DocumentJson = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ImportedAudits", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditReports",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ScanId = table.Column<int>(type: "INTEGER", nullable: true),
                    ImportedAuditId = table.Column<int>(type: "INTEGER", nullable: true),
                    Format = table.Column<int>(type: "INTEGER", nullable: false),
                    FileName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    SizeBytes = table.Column<long>(type: "INTEGER", nullable: false),
                    Sha256 = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Language = table.Column<string>(type: "TEXT", maxLength: 5, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditReports", x => x.Id);
                    table.CheckConstraint("CK_AuditReports_Source", "(ScanId IS NULL) <> (ImportedAuditId IS NULL)");
                    table.ForeignKey(
                        name: "FK_AuditReports_ImportedAudits_ImportedAuditId",
                        column: x => x.ImportedAuditId,
                        principalTable: "ImportedAudits",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AuditReports_Scans_ScanId",
                        column: x => x.ScanId,
                        principalTable: "Scans",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditAiSummaries_ScanId",
                table: "AuditAiSummaries",
                column: "ScanId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuditReports_CreatedAt",
                table: "AuditReports",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_AuditReports_ImportedAuditId",
                table: "AuditReports",
                column: "ImportedAuditId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditReports_ScanId",
                table: "AuditReports",
                column: "ScanId");

            migrationBuilder.CreateIndex(
                name: "IX_ImportedAudits_Sha256",
                table: "ImportedAudits",
                column: "Sha256",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditAiSummaries");

            migrationBuilder.DropTable(
                name: "AuditReports");

            migrationBuilder.DropTable(
                name: "ImportedAudits");
        }
    }
}
