using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class InitialSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Devices",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    AppInstanceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceType = table.Column<int>(type: "int", nullable: false, defaultValue: 1),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Devices", x => x.Id);
                    table.UniqueConstraint("AK_Devices_UniqueId", x => x.UniqueId);
                });

            migrationBuilder.CreateTable(
                name: "MobileNumbers",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Number = table.Column<string>(type: "nvarchar(18)", maxLength: 18, nullable: false),
                    Region = table.Column<string>(type: "nvarchar(2)", maxLength: 2, nullable: true),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MobileNumbers", x => x.Id);
                    table.UniqueConstraint("AK_MobileNumbers_UniqueId", x => x.UniqueId);
                });

            migrationBuilder.CreateTable(
                name: "MobileDevices",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MobileNumberId = table.Column<long>(type: "bigint", nullable: false),
                    DeviceId = table.Column<long>(type: "bigint", nullable: false),
                    RelationshipType = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true, defaultValue: "primary"),
                    IsActive = table.Column<bool>(type: "bit", nullable: false, defaultValue: true),
                    LastUsedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MobileDevices", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MobileDevices_Devices",
                        column: x => x.DeviceId,
                        principalTable: "Devices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_MobileDevices_MobileNumbers",
                        column: x => x.MobileNumberId,
                        principalTable: "MobileNumbers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "VerificationFlows",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MobileNumberId = table.Column<long>(type: "bigint", nullable: false),
                    AppDeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Status = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false, defaultValue: "pending"),
                    Purpose = table.Column<string>(type: "nvarchar(30)", maxLength: 30, nullable: false, defaultValue: "unspecified"),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    OtpCount = table.Column<short>(type: "smallint", nullable: false, defaultValue: (short)0),
                    ConnectionId = table.Column<long>(type: "bigint", nullable: true),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VerificationFlows", x => x.Id);
                    table.UniqueConstraint("AK_VerificationFlows_UniqueId", x => x.UniqueId);
                    table.CheckConstraint("CHK_VerificationFlows_Purpose", "Purpose IN ('unspecified', 'registration', 'login', 'password_recovery', 'update_phone')");
                    table.CheckConstraint("CHK_VerificationFlows_Status", "Status IN ('pending', 'verified', 'expired', 'failed')");
                    table.ForeignKey(
                        name: "FK_VerificationFlows_Devices",
                        column: x => x.AppDeviceId,
                        principalTable: "Devices",
                        principalColumn: "UniqueId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_VerificationFlows_MobileNumbers",
                        column: x => x.MobileNumberId,
                        principalTable: "MobileNumbers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Memberships",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MobileNumberId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AppDeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    VerificationFlowId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SecureKey = table.Column<byte[]>(type: "VARBINARY(176)", nullable: true),
                    MaskingKey = table.Column<byte[]>(type: "VARBINARY(32)", nullable: true),
                    Status = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false, defaultValue: "inactive"),
                    CreationStatus = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: true),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Memberships", x => x.Id);
                    table.UniqueConstraint("AK_Memberships_UniqueId", x => x.UniqueId);
                    table.CheckConstraint("CHK_Memberships_CreationStatus", "CreationStatus IN ('otp_verified', 'secure_key_set', 'passphrase_set')");
                    table.CheckConstraint("CHK_Memberships_Status", "Status IN ('active', 'inactive')");
                    table.ForeignKey(
                        name: "FK_Memberships_Devices",
                        column: x => x.AppDeviceId,
                        principalTable: "Devices",
                        principalColumn: "UniqueId");
                    table.ForeignKey(
                        name: "FK_Memberships_MobileNumbers",
                        column: x => x.MobileNumberId,
                        principalTable: "MobileNumbers",
                        principalColumn: "UniqueId");
                    table.ForeignKey(
                        name: "FK_Memberships_VerificationFlows",
                        column: x => x.VerificationFlowId,
                        principalTable: "VerificationFlows",
                        principalColumn: "UniqueId");
                });

            migrationBuilder.CreateTable(
                name: "OtpCodes",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    VerificationFlowId = table.Column<long>(type: "bigint", nullable: false),
                    OtpValue = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    OtpSalt = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    Status = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false, defaultValue: "active"),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    AttemptCount = table.Column<short>(type: "smallint", nullable: false, defaultValue: (short)0),
                    VerifiedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OtpCodes", x => x.Id);
                    table.CheckConstraint("CHK_OtpCodes_Status", "Status IN ('active', 'used', 'expired', 'invalid')");
                    table.ForeignKey(
                        name: "FK_OtpCodes_VerificationFlows",
                        column: x => x.VerificationFlowId,
                        principalTable: "VerificationFlows",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "LoginAttempts",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MembershipUniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    MobileNumber = table.Column<string>(type: "nvarchar(18)", maxLength: 18, nullable: true),
                    Outcome = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                    IsSuccess = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    Timestamp = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    LockedUntil = table.Column<DateTime>(type: "DATETIME2", nullable: true),
                    Status = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: true),
                    ErrorMessage = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: true),
                    SessionId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    AttemptedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    SuccessfulAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LoginAttempts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_LoginAttempts_Memberships",
                        column: x => x.MembershipUniqueId,
                        principalTable: "Memberships",
                        principalColumn: "UniqueId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "LogoutAudits",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MembershipUniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ConnectId = table.Column<long>(type: "bigint", nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    LoggedOutAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LogoutAudits", x => x.Id);
                    table.ForeignKey(
                        name: "FK_LogoutAudits_Memberships",
                        column: x => x.MembershipUniqueId,
                        principalTable: "Memberships",
                        principalColumn: "UniqueId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MasterKeyShares",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MembershipUniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ShareIndex = table.Column<int>(type: "int", nullable: false),
                    EncryptedShare = table.Column<byte[]>(type: "VARBINARY(128)", nullable: false),
                    ShareMetadata = table.Column<string>(type: "NVARCHAR(500)", nullable: false),
                    StorageLocation = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MasterKeyShares", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MasterKeyShares_Memberships",
                        column: x => x.MembershipUniqueId,
                        principalTable: "Memberships",
                        principalColumn: "UniqueId");
                });

            migrationBuilder.CreateTable(
                name: "FailedOtpAttempts",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    OtpRecordId = table.Column<long>(type: "bigint", nullable: false),
                    AttemptedValue = table.Column<string>(type: "nvarchar(10)", maxLength: 10, nullable: false),
                    FailureReason = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    AttemptedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FailedOtpAttempts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_FailedOtpAttempts_OtpCodes",
                        column: x => x.OtpRecordId,
                        principalTable: "OtpCodes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Device_CreatedAt",
                table: "Devices",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Device_UpdatedAt",
                table: "Devices",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Devices_AppInstanceId",
                table: "Devices",
                column: "AppInstanceId");

            migrationBuilder.CreateIndex(
                name: "IX_Devices_DeviceType",
                table: "Devices",
                column: "DeviceType",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "UQ_Device_UniqueId",
                table: "Devices",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UQ_Devices_DeviceId",
                table: "Devices",
                column: "DeviceId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_FailedOtpAttempt_CreatedAt",
                table: "FailedOtpAttempts",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_FailedOtpAttempt_UpdatedAt",
                table: "FailedOtpAttempts",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_FailedOtpAttempts_AttemptedAt",
                table: "FailedOtpAttempts",
                column: "AttemptedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_FailedOtpAttempts_OtpRecordId",
                table: "FailedOtpAttempts",
                column: "OtpRecordId");

            migrationBuilder.CreateIndex(
                name: "UQ_FailedOtpAttempt_UniqueId",
                table: "FailedOtpAttempts",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempt_CreatedAt",
                table: "LoginAttempts",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempt_UpdatedAt",
                table: "LoginAttempts",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_IsSuccess",
                table: "LoginAttempts",
                column: "IsSuccess",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_Lockout",
                table: "LoginAttempts",
                columns: new[] { "MobileNumber", "LockedUntil" },
                filter: "IsDeleted = 0 AND LockedUntil IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_Membership_AttemptedAt",
                table: "LoginAttempts",
                columns: new[] { "MembershipUniqueId", "AttemptedAt" },
                descending: new[] { false, true },
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_MobileNumber",
                table: "LoginAttempts",
                column: "MobileNumber",
                filter: "IsDeleted = 0 AND MobileNumber IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_RateLimiting",
                table: "LoginAttempts",
                columns: new[] { "MobileNumber", "Timestamp" },
                descending: new[] { false, true },
                filter: "IsDeleted = 0 AND MobileNumber IS NOT NULL AND LockedUntil IS NULL")
                .Annotation("SqlServer:Include", new[] { "IsSuccess" });

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_SessionId",
                table: "LoginAttempts",
                column: "SessionId",
                filter: "IsDeleted = 0 AND SessionId IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_Status",
                table: "LoginAttempts",
                column: "Status",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "UQ_LoginAttempt_UniqueId",
                table: "LoginAttempts",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LogoutAudit_CreatedAt",
                table: "LogoutAudits",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_LogoutAudit_UpdatedAt",
                table: "LogoutAudits",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_LogoutAudits_ConnectId",
                table: "LogoutAudits",
                column: "ConnectId",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_LogoutAudits_LoggedOutAt",
                table: "LogoutAudits",
                column: "LoggedOutAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_LogoutAudits_Membership_LoggedOutAt",
                table: "LogoutAudits",
                columns: new[] { "MembershipUniqueId", "LoggedOutAt" },
                descending: new[] { false, true },
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "UQ_LogoutAudit_UniqueId",
                table: "LogoutAudits",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MasterKeyShare_CreatedAt",
                table: "MasterKeyShares",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MasterKeyShare_UpdatedAt",
                table: "MasterKeyShares",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MasterKeyShares_ShareIndex",
                table: "MasterKeyShares",
                column: "ShareIndex");

            migrationBuilder.CreateIndex(
                name: "UQ_MasterKeyShare_UniqueId",
                table: "MasterKeyShares",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UQ_MasterKeyShares_MembershipShare",
                table: "MasterKeyShares",
                columns: new[] { "MembershipUniqueId", "ShareIndex" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Membership_CreatedAt",
                table: "Memberships",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Membership_UpdatedAt",
                table: "Memberships",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Memberships_AppDeviceId",
                table: "Memberships",
                column: "AppDeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_Memberships_MobileNumberId",
                table: "Memberships",
                column: "MobileNumberId");

            migrationBuilder.CreateIndex(
                name: "IX_Memberships_Status",
                table: "Memberships",
                column: "Status",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Memberships_VerificationFlowId",
                table: "Memberships",
                column: "VerificationFlowId");

            migrationBuilder.CreateIndex(
                name: "UQ_Memberships_ActiveMembership",
                table: "Memberships",
                columns: new[] { "MobileNumberId", "AppDeviceId", "IsDeleted" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UQ_Memberships_UniqueId",
                table: "Memberships",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MobileDevice_CreatedAt",
                table: "MobileDevices",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MobileDevice_UpdatedAt",
                table: "MobileDevices",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MobileDevices_DeviceId",
                table: "MobileDevices",
                column: "DeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_MobileDevices_IsActive",
                table: "MobileDevices",
                column: "IsActive",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MobileDevices_LastUsedAt",
                table: "MobileDevices",
                column: "LastUsedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0 AND LastUsedAt IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_MobileDevices_MobileNumberId",
                table: "MobileDevices",
                column: "MobileNumberId");

            migrationBuilder.CreateIndex(
                name: "UQ_MobileDevice_UniqueId",
                table: "MobileDevices",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UQ_MobileDevices_PhoneDevice",
                table: "MobileDevices",
                columns: new[] { "MobileNumberId", "DeviceId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MobileNumber_UpdatedAt",
                table: "MobileNumbers",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MobileNumbers_CreatedAt",
                table: "MobileNumbers",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MobileNumbers_MobileNumber_Region",
                table: "MobileNumbers",
                columns: new[] { "Number", "Region" },
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MobileNumbers_Region",
                table: "MobileNumbers",
                column: "Region",
                filter: "IsDeleted = 0 AND Region IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "UQ_MobileNumber_UniqueId",
                table: "MobileNumbers",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UQ_MobileNumbers_ActiveNumberRegion",
                table: "MobileNumbers",
                columns: new[] { "Number", "Region", "IsDeleted" },
                unique: true,
                filter: "[Region] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_OtpCode_CreatedAt",
                table: "OtpCodes",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_OtpCode_UpdatedAt",
                table: "OtpCodes",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_OtpCodes_ExpiresAt",
                table: "OtpCodes",
                column: "ExpiresAt",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_OtpCodes_Status",
                table: "OtpCodes",
                column: "Status",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_OtpCodes_VerificationFlowId",
                table: "OtpCodes",
                column: "VerificationFlowId");

            migrationBuilder.CreateIndex(
                name: "UQ_OtpCode_UniqueId",
                table: "OtpCodes",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlow_CreatedAt",
                table: "VerificationFlows",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlow_UpdatedAt",
                table: "VerificationFlows",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlows_ActiveFlowRecovery",
                table: "VerificationFlows",
                columns: new[] { "MobileNumberId", "AppDeviceId", "Purpose", "Status", "ExpiresAt" },
                filter: "IsDeleted = 0 AND Status = 'pending'")
                .Annotation("SqlServer:Include", new[] { "UniqueId", "ConnectionId", "OtpCount", "CreatedAt", "UpdatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlows_AppDeviceId",
                table: "VerificationFlows",
                column: "AppDeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlows_ExpiresAt",
                table: "VerificationFlows",
                column: "ExpiresAt",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlows_MobileNumberId",
                table: "VerificationFlows",
                column: "MobileNumberId");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlows_Status",
                table: "VerificationFlows",
                column: "Status",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "UQ_VerificationFlow_UniqueId",
                table: "VerificationFlows",
                column: "UniqueId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FailedOtpAttempts");

            migrationBuilder.DropTable(
                name: "LoginAttempts");

            migrationBuilder.DropTable(
                name: "LogoutAudits");

            migrationBuilder.DropTable(
                name: "MasterKeyShares");

            migrationBuilder.DropTable(
                name: "MobileDevices");

            migrationBuilder.DropTable(
                name: "OtpCodes");

            migrationBuilder.DropTable(
                name: "Memberships");

            migrationBuilder.DropTable(
                name: "VerificationFlows");

            migrationBuilder.DropTable(
                name: "Devices");

            migrationBuilder.DropTable(
                name: "MobileNumbers");
        }
    }
}
