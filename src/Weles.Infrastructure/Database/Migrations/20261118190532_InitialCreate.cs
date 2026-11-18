using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Weles.Infrastructure.Database.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "NetworkSegments",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Cidr = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Gateway = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    FirstSeenAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastSeenAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NetworkSegments", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ScanTargets",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    IsApproved = table.Column<bool>(type: "INTEGER", nullable: false),
                    ApprovedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    AllowPublicAddresses = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsDemo = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanTargets", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Settings",
                columns: table => new
                {
                    Key = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Value = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Settings", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "Vulnerabilities",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    CveId = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Description = table.Column<string>(type: "TEXT", nullable: true),
                    CvssScore = table.Column<double>(type: "REAL", nullable: true),
                    CvssVector = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    CvssVersion = table.Column<string>(type: "TEXT", maxLength: 8, nullable: true),
                    Severity = table.Column<int>(type: "INTEGER", nullable: true),
                    EpssScore = table.Column<double>(type: "REAL", nullable: true),
                    EpssPercentile = table.Column<double>(type: "REAL", nullable: true),
                    IsKnownExploited = table.Column<bool>(type: "INTEGER", nullable: false),
                    KevDateAdded = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Source = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    PublishedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastModifiedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ReferencesJson = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vulnerabilities", x => x.Id);
                    table.CheckConstraint("CK_Vulnerability_Cvss", "CvssScore IS NULL OR (CvssScore >= 0 AND CvssScore <= 10)");
                    table.CheckConstraint("CK_Vulnerability_Epss", "EpssScore IS NULL OR (EpssScore >= 0 AND EpssScore <= 1)");
                });

            migrationBuilder.CreateTable(
                name: "Assets",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    Hostname = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    PrimaryIpAddress = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    MacAddress = table.Column<string>(type: "TEXT", maxLength: 17, nullable: true),
                    Vendor = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    AssetType = table.Column<int>(type: "INTEGER", nullable: false),
                    OsFamily = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    OsDetails = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Criticality = table.Column<int>(type: "INTEGER", nullable: false),
                    Notes = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    NetworkSegmentId = table.Column<int>(type: "INTEGER", nullable: true),
                    CurrentRiskScore = table.Column<double>(type: "REAL", nullable: true),
                    CurrentRiskLevel = table.Column<int>(type: "INTEGER", nullable: true),
                    FirstSeenAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastSeenAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    IsDemo = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Assets", x => x.Id);
                    table.CheckConstraint("CK_Asset_RiskScore", "CurrentRiskScore IS NULL OR (CurrentRiskScore >= 0 AND CurrentRiskScore <= 100)");
                    table.ForeignKey(
                        name: "FK_Assets_NetworkSegments_NetworkSegmentId",
                        column: x => x.NetworkSegmentId,
                        principalTable: "NetworkSegments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "Scans",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ScanTargetId = table.Column<int>(type: "INTEGER", nullable: false),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    Trigger = table.Column<int>(type: "INTEGER", nullable: false),
                    PortSpecification = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    StartedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CompletedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    HostsAlive = table.Column<int>(type: "INTEGER", nullable: false),
                    OpenPorts = table.Column<int>(type: "INTEGER", nullable: false),
                    ErrorMessage = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    IsDemo = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Scans", x => x.Id);
                    table.CheckConstraint("CK_Scan_Counters", "HostsAlive >= 0 AND OpenPorts >= 0");
                    table.ForeignKey(
                        name: "FK_Scans_ScanTargets_ScanTargetId",
                        column: x => x.ScanTargetId,
                        principalTable: "ScanTargets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "ScanTargetEntries",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ScanTargetId = table.Column<int>(type: "INTEGER", nullable: false),
                    Value = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    Kind = table.Column<int>(type: "INTEGER", nullable: false),
                    IsExclusion = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanTargetEntries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ScanTargetEntries_ScanTargets_ScanTargetId",
                        column: x => x.ScanTargetId,
                        principalTable: "ScanTargets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "VulnerabilityAffectedProducts",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    VulnerabilityId = table.Column<int>(type: "INTEGER", nullable: false),
                    Vendor = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    Product = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    Cpe = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    VersionStartIncluding = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    VersionStartExcluding = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    VersionEndIncluding = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    VersionEndExcluding = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VulnerabilityAffectedProducts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VulnerabilityAffectedProducts_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DiscoveredHosts",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ScanId = table.Column<int>(type: "INTEGER", nullable: false),
                    AssetId = table.Column<int>(type: "INTEGER", nullable: true),
                    IpAddress = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Hostname = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    MacAddress = table.Column<string>(type: "TEXT", maxLength: 17, nullable: true),
                    Vendor = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    DiscoveryMethods = table.Column<int>(type: "INTEGER", nullable: false),
                    RoundTripMs = table.Column<double>(type: "REAL", nullable: true),
                    Ttl = table.Column<int>(type: "INTEGER", nullable: true),
                    OsGuess = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    DiscoveredAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DiscoveredHosts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DiscoveredHosts_Assets_AssetId",
                        column: x => x.AssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_DiscoveredHosts_Scans_ScanId",
                        column: x => x.ScanId,
                        principalTable: "Scans",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RiskFindings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ScanId = table.Column<int>(type: "INTEGER", nullable: false),
                    AssetId = table.Column<int>(type: "INTEGER", nullable: false),
                    RuleId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    Category = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Level = table.Column<int>(type: "INTEGER", nullable: false),
                    Score = table.Column<double>(type: "REAL", nullable: false),
                    Evidence = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    Recommendation = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RiskFindings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RiskFindings_Assets_AssetId",
                        column: x => x.AssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RiskFindings_Scans_ScanId",
                        column: x => x.ScanId,
                        principalTable: "Scans",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RiskScores",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ScanId = table.Column<int>(type: "INTEGER", nullable: false),
                    AssetId = table.Column<int>(type: "INTEGER", nullable: true),
                    Score = table.Column<double>(type: "REAL", nullable: false),
                    Level = table.Column<int>(type: "INTEGER", nullable: false),
                    BreakdownJson = table.Column<string>(type: "TEXT", nullable: false),
                    CalculatedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RiskScores", x => x.Id);
                    table.CheckConstraint("CK_RiskScore_Score", "Score >= 0 AND Score <= 100");
                    table.ForeignKey(
                        name: "FK_RiskScores_Assets_AssetId",
                        column: x => x.AssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RiskScores_Scans_ScanId",
                        column: x => x.ScanId,
                        principalTable: "Scans",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DiscoveredPorts",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DiscoveredHostId = table.Column<int>(type: "INTEGER", nullable: false),
                    Port = table.Column<int>(type: "INTEGER", nullable: false),
                    Protocol = table.Column<int>(type: "INTEGER", nullable: false),
                    State = table.Column<int>(type: "INTEGER", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DiscoveredPorts", x => x.Id);
                    table.CheckConstraint("CK_DiscoveredPort_Port", "Port BETWEEN 1 AND 65535");
                    table.ForeignKey(
                        name: "FK_DiscoveredPorts_DiscoveredHosts_DiscoveredHostId",
                        column: x => x.DiscoveredHostId,
                        principalTable: "DiscoveredHosts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DiscoveredServices",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DiscoveredPortId = table.Column<int>(type: "INTEGER", nullable: false),
                    ServiceName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    Product = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    Vendor = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    Version = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    Cpe = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Banner = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    Confidence = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectionMethod = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    IsTls = table.Column<bool>(type: "INTEGER", nullable: false),
                    ExtraInfoJson = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DiscoveredServices", x => x.Id);
                    table.CheckConstraint("CK_DiscoveredService_Confidence", "Confidence BETWEEN 0 AND 100");
                    table.ForeignKey(
                        name: "FK_DiscoveredServices_DiscoveredPorts_DiscoveredPortId",
                        column: x => x.DiscoveredPortId,
                        principalTable: "DiscoveredPorts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AssetVulnerabilities",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    AssetId = table.Column<int>(type: "INTEGER", nullable: false),
                    VulnerabilityId = table.Column<int>(type: "INTEGER", nullable: false),
                    DiscoveredServiceId = table.Column<int>(type: "INTEGER", nullable: true),
                    ScanId = table.Column<int>(type: "INTEGER", nullable: true),
                    MatchStatus = table.Column<int>(type: "INTEGER", nullable: false),
                    MatchConfidence = table.Column<int>(type: "INTEGER", nullable: false),
                    MatchReason = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    FirstDetectedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastDetectedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AssetVulnerabilities", x => x.Id);
                    table.CheckConstraint("CK_AssetVulnerability_Confidence", "MatchConfidence BETWEEN 0 AND 100");
                    table.ForeignKey(
                        name: "FK_AssetVulnerabilities_Assets_AssetId",
                        column: x => x.AssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AssetVulnerabilities_DiscoveredServices_DiscoveredServiceId",
                        column: x => x.DiscoveredServiceId,
                        principalTable: "DiscoveredServices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_AssetVulnerabilities_Scans_ScanId",
                        column: x => x.ScanId,
                        principalTable: "Scans",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_AssetVulnerabilities_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Certificates",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DiscoveredServiceId = table.Column<int>(type: "INTEGER", nullable: false),
                    Subject = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    Issuer = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    NotBefore = table.Column<DateTime>(type: "TEXT", nullable: false),
                    NotAfter = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Thumbprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    SerialNumber = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    SubjectAlternativeNames = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    KeyAlgorithm = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    KeySize = table.Column<int>(type: "INTEGER", nullable: true),
                    SignatureAlgorithm = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    TlsProtocol = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    IsSelfSigned = table.Column<bool>(type: "INTEGER", nullable: false),
                    HostnameMatches = table.Column<bool>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Certificates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Certificates_DiscoveredServices_DiscoveredServiceId",
                        column: x => x.DiscoveredServiceId,
                        principalTable: "DiscoveredServices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Assets_CurrentRiskLevel",
                table: "Assets",
                column: "CurrentRiskLevel");

            migrationBuilder.CreateIndex(
                name: "IX_Assets_LastSeenAt",
                table: "Assets",
                column: "LastSeenAt");

            migrationBuilder.CreateIndex(
                name: "IX_Assets_MacAddress",
                table: "Assets",
                column: "MacAddress");

            migrationBuilder.CreateIndex(
                name: "IX_Assets_NetworkSegmentId",
                table: "Assets",
                column: "NetworkSegmentId");

            migrationBuilder.CreateIndex(
                name: "IX_Assets_PrimaryIpAddress",
                table: "Assets",
                column: "PrimaryIpAddress");

            migrationBuilder.CreateIndex(
                name: "IX_AssetVulnerabilities_AssetId_VulnerabilityId_DiscoveredServiceId",
                table: "AssetVulnerabilities",
                columns: new[] { "AssetId", "VulnerabilityId", "DiscoveredServiceId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AssetVulnerabilities_DiscoveredServiceId",
                table: "AssetVulnerabilities",
                column: "DiscoveredServiceId");

            migrationBuilder.CreateIndex(
                name: "IX_AssetVulnerabilities_ScanId",
                table: "AssetVulnerabilities",
                column: "ScanId");

            migrationBuilder.CreateIndex(
                name: "IX_AssetVulnerabilities_Status",
                table: "AssetVulnerabilities",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_AssetVulnerabilities_VulnerabilityId",
                table: "AssetVulnerabilities",
                column: "VulnerabilityId");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_DiscoveredServiceId",
                table: "Certificates",
                column: "DiscoveredServiceId");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_NotAfter",
                table: "Certificates",
                column: "NotAfter");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_Thumbprint",
                table: "Certificates",
                column: "Thumbprint");

            migrationBuilder.CreateIndex(
                name: "IX_DiscoveredHosts_AssetId",
                table: "DiscoveredHosts",
                column: "AssetId");

            migrationBuilder.CreateIndex(
                name: "IX_DiscoveredHosts_ScanId_IpAddress",
                table: "DiscoveredHosts",
                columns: new[] { "ScanId", "IpAddress" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DiscoveredPorts_DiscoveredHostId_Port_Protocol",
                table: "DiscoveredPorts",
                columns: new[] { "DiscoveredHostId", "Port", "Protocol" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DiscoveredServices_DiscoveredPortId",
                table: "DiscoveredServices",
                column: "DiscoveredPortId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DiscoveredServices_Product_Version",
                table: "DiscoveredServices",
                columns: new[] { "Product", "Version" });

            migrationBuilder.CreateIndex(
                name: "IX_NetworkSegments_Cidr",
                table: "NetworkSegments",
                column: "Cidr",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RiskFindings_AssetId",
                table: "RiskFindings",
                column: "AssetId");

            migrationBuilder.CreateIndex(
                name: "IX_RiskFindings_ScanId_Level",
                table: "RiskFindings",
                columns: new[] { "ScanId", "Level" });

            migrationBuilder.CreateIndex(
                name: "IX_RiskScores_AssetId",
                table: "RiskScores",
                column: "AssetId");

            migrationBuilder.CreateIndex(
                name: "IX_RiskScores_ScanId_AssetId",
                table: "RiskScores",
                columns: new[] { "ScanId", "AssetId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Scans_CreatedAt",
                table: "Scans",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_Scans_ScanTargetId",
                table: "Scans",
                column: "ScanTargetId");

            migrationBuilder.CreateIndex(
                name: "IX_Scans_Status_StartedAt",
                table: "Scans",
                columns: new[] { "Status", "StartedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_ScanTargetEntries_ScanTargetId_Value_IsExclusion",
                table: "ScanTargetEntries",
                columns: new[] { "ScanTargetId", "Value", "IsExclusion" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScanTargets_Name",
                table: "ScanTargets",
                column: "Name");

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_CveId",
                table: "Vulnerabilities",
                column: "CveId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_IsKnownExploited",
                table: "Vulnerabilities",
                column: "IsKnownExploited");

            migrationBuilder.CreateIndex(
                name: "IX_VulnerabilityAffectedProducts_Vendor_Product",
                table: "VulnerabilityAffectedProducts",
                columns: new[] { "Vendor", "Product" });

            migrationBuilder.CreateIndex(
                name: "IX_VulnerabilityAffectedProducts_VulnerabilityId",
                table: "VulnerabilityAffectedProducts",
                column: "VulnerabilityId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AssetVulnerabilities");

            migrationBuilder.DropTable(
                name: "Certificates");

            migrationBuilder.DropTable(
                name: "RiskFindings");

            migrationBuilder.DropTable(
                name: "RiskScores");

            migrationBuilder.DropTable(
                name: "ScanTargetEntries");

            migrationBuilder.DropTable(
                name: "Settings");

            migrationBuilder.DropTable(
                name: "VulnerabilityAffectedProducts");

            migrationBuilder.DropTable(
                name: "DiscoveredServices");

            migrationBuilder.DropTable(
                name: "Vulnerabilities");

            migrationBuilder.DropTable(
                name: "DiscoveredPorts");

            migrationBuilder.DropTable(
                name: "DiscoveredHosts");

            migrationBuilder.DropTable(
                name: "Assets");

            migrationBuilder.DropTable(
                name: "Scans");

            migrationBuilder.DropTable(
                name: "NetworkSegments");

            migrationBuilder.DropTable(
                name: "ScanTargets");
        }
    }
}
