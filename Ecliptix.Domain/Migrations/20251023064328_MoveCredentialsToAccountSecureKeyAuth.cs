using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class MoveCredentialsToAccountSecureKeyAuth : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Memberships_Login_Covering",
                table: "Memberships");

            migrationBuilder.DropCheckConstraint(
                name: "CHK_Memberships_Credentials_Consistency",
                table: "Memberships");

            migrationBuilder.DropColumn(
                name: "CreatedBy",
                table: "VerificationFlows");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "VerificationFlows");

            migrationBuilder.DropColumn(
                name: "DeletedBy",
                table: "VerificationFlows");

            migrationBuilder.DropColumn(
                name: "UpdatedBy",
                table: "VerificationFlows");

            migrationBuilder.DropColumn(
                name: "CreatedBy",
                table: "OtpCodes");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "OtpCodes");

            migrationBuilder.DropColumn(
                name: "DeletedBy",
                table: "OtpCodes");

            migrationBuilder.DropColumn(
                name: "UpdatedBy",
                table: "OtpCodes");

            migrationBuilder.DropColumn(
                name: "CreatedBy",
                table: "MobileNumbers");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "MobileNumbers");

            migrationBuilder.DropColumn(
                name: "DeletedBy",
                table: "MobileNumbers");

            migrationBuilder.DropColumn(
                name: "UpdatedBy",
                table: "MobileNumbers");

            migrationBuilder.DropColumn(
                name: "CreatedBy",
                table: "Memberships");

            migrationBuilder.DropColumn(
                name: "CredentialsVersion",
                table: "Memberships");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "Memberships");

            migrationBuilder.DropColumn(
                name: "DeletedBy",
                table: "Memberships");

            migrationBuilder.DropColumn(
                name: "MaskingKey",
                table: "Memberships");

            migrationBuilder.DropColumn(
                name: "SecureKey",
                table: "Memberships");

            migrationBuilder.DropColumn(
                name: "UpdatedBy",
                table: "Memberships");

            migrationBuilder.DropColumn(
                name: "CreatedBy",
                table: "MasterKeyShares");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "MasterKeyShares");

            migrationBuilder.DropColumn(
                name: "DeletedBy",
                table: "MasterKeyShares");

            migrationBuilder.DropColumn(
                name: "UpdatedBy",
                table: "MasterKeyShares");

            migrationBuilder.DropColumn(
                name: "CreatedBy",
                table: "LogoutAudits");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "LogoutAudits");

            migrationBuilder.DropColumn(
                name: "DeletedBy",
                table: "LogoutAudits");

            migrationBuilder.DropColumn(
                name: "UpdatedBy",
                table: "LogoutAudits");

            migrationBuilder.DropColumn(
                name: "CreatedBy",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "DeletedBy",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "UpdatedBy",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "CreatedBy",
                table: "FailedOtpAttempts");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "FailedOtpAttempts");

            migrationBuilder.DropColumn(
                name: "DeletedBy",
                table: "FailedOtpAttempts");

            migrationBuilder.DropColumn(
                name: "UpdatedBy",
                table: "FailedOtpAttempts");

            migrationBuilder.DropColumn(
                name: "CreatedBy",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "DeletedBy",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "UpdatedBy",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "CreatedBy",
                table: "DeviceContexts");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "DeviceContexts");

            migrationBuilder.DropColumn(
                name: "DeletedBy",
                table: "DeviceContexts");

            migrationBuilder.DropColumn(
                name: "UpdatedBy",
                table: "DeviceContexts");

            migrationBuilder.DropColumn(
                name: "CreatedBy",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "CredentialsVersion",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "DeletedBy",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "MaskingKey",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "SecureKey",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "UpdatedBy",
                table: "Accounts");

            migrationBuilder.CreateTable(
                name: "AccountPinAuth",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    SecureKey = table.Column<byte[]>(type: "VARBINARY(176)", nullable: false),
                    MaskingKey = table.Column<byte[]>(type: "VARBINARY(32)", nullable: false),
                    CredentialsVersion = table.Column<int>(type: "int", nullable: false, defaultValue: 1),
                    IsPrimary = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false, defaultValue: true),
                    IsDeviceSpecific = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    PinLength = table.Column<int>(type: "int", nullable: false, defaultValue: 6),
                    LastUsedAt = table.Column<DateTimeOffset>(type: "DATETIMEOFFSET", nullable: true),
                    FailedAttempts = table.Column<int>(type: "int", nullable: false, defaultValue: 0),
                    LockedUntil = table.Column<DateTimeOffset>(type: "DATETIMEOFFSET", nullable: true),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSDATETIMEOFFSET()"),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSDATETIMEOFFSET()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AccountPinAuth", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AccountPinAuth_Accounts",
                        column: x => x.AccountId,
                        principalTable: "Accounts",
                        principalColumn: "UniqueId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AccountPinAuth_Devices",
                        column: x => x.DeviceId,
                        principalTable: "Devices",
                        principalColumn: "UniqueId");
                });

            migrationBuilder.CreateTable(
                name: "AccountSecureKeyAuth",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SecureKey = table.Column<byte[]>(type: "VARBINARY(176)", nullable: false),
                    MaskingKey = table.Column<byte[]>(type: "VARBINARY(32)", nullable: false),
                    CredentialsVersion = table.Column<int>(type: "int", nullable: false, defaultValue: 1),
                    IsPrimary = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false, defaultValue: true),
                    LastUsedAt = table.Column<DateTimeOffset>(type: "DATETIMEOFFSET", nullable: true),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "DATETIMEOFFSET", nullable: true),
                    FailedAttempts = table.Column<int>(type: "int", nullable: false, defaultValue: 0),
                    LockedUntil = table.Column<DateTimeOffset>(type: "DATETIMEOFFSET", nullable: true),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSDATETIMEOFFSET()"),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSDATETIMEOFFSET()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AccountSecureKeyAuth", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AccountSecureKeyAuth_Accounts",
                        column: x => x.AccountId,
                        principalTable: "Accounts",
                        principalColumn: "UniqueId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "VerificationLogs",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MembershipId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    MobileNumberId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Purpose = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    Status = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false),
                    OtpCount = table.Column<short>(type: "smallint", nullable: false, defaultValue: (short)0),
                    VerifiedAt = table.Column<DateTimeOffset>(type: "DATETIMEOFFSET", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "DATETIMEOFFSET", nullable: true),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSDATETIMEOFFSET()"),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSDATETIMEOFFSET()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VerificationLogs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VerificationLogs_Accounts",
                        column: x => x.AccountId,
                        principalTable: "Accounts",
                        principalColumn: "UniqueId");
                    table.ForeignKey(
                        name: "FK_VerificationLogs_Devices",
                        column: x => x.DeviceId,
                        principalTable: "Devices",
                        principalColumn: "UniqueId");
                    table.ForeignKey(
                        name: "FK_VerificationLogs_Memberships",
                        column: x => x.MembershipId,
                        principalTable: "Memberships",
                        principalColumn: "UniqueId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_VerificationLogs_MobileNumbers",
                        column: x => x.MobileNumberId,
                        principalTable: "MobileNumbers",
                        principalColumn: "UniqueId");
                });


            migrationBuilder.CreateIndex(
                name: "IX_Memberships_Login_Covering",
                table: "Memberships",
                column: "MobileNumberId",
                filter: "IsDeleted = 0 AND Status = 'active'")
                .Annotation("SqlServer:Include", new[] { "UniqueId", "CreationStatus" });

            migrationBuilder.CreateIndex(
                name: "IX_AccountPinAuth_Account_Enabled",
                table: "AccountPinAuth",
                column: "AccountId",
                filter: "IsDeleted = 0 AND IsEnabled = 1");

            migrationBuilder.CreateIndex(
                name: "IX_AccountPinAuth_Covering",
                table: "AccountPinAuth",
                columns: new[] { "AccountId", "DeviceId" },
                filter: "IsDeleted = 0 AND IsEnabled = 1")
                .Annotation("SqlServer:Include", new[] { "UniqueId", "SecureKey", "MaskingKey", "CredentialsVersion", "IsDeviceSpecific" });

            migrationBuilder.CreateIndex(
                name: "UX_AccountPinAuth_Account_Device",
                table: "AccountPinAuth",
                columns: new[] { "AccountId", "DeviceId" },
                unique: true,
                filter: "IsDeleted = 0 AND IsDeviceSpecific = 1 AND DeviceId IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_AccountPinAuth_DeviceId",
                table: "AccountPinAuth",
                column: "DeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_AccountPinAuthEntity_CreatedAt",
                table: "AccountPinAuth",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_AccountPinAuthEntity_UpdatedAt",
                table: "AccountPinAuth",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "UQ_AccountPinAuthEntity_UniqueId",
                table: "AccountPinAuth",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AccountSecureKeyAuth_Account_Enabled",
                table: "AccountSecureKeyAuth",
                column: "AccountId",
                filter: "IsDeleted = 0 AND IsEnabled = 1");

            migrationBuilder.CreateIndex(
                name: "IX_AccountSecureKeyAuth_Covering",
                table: "AccountSecureKeyAuth",
                column: "AccountId",
                filter: "IsDeleted = 0 AND IsEnabled = 1")
                .Annotation("SqlServer:Include", new[] { "UniqueId", "SecureKey", "MaskingKey", "CredentialsVersion", "IsPrimary" });

            migrationBuilder.CreateIndex(
                name: "IX_AccountSecureKeyAuthEntity_CreatedAt",
                table: "AccountSecureKeyAuth",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_AccountSecureKeyAuthEntity_UpdatedAt",
                table: "AccountSecureKeyAuth",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "UQ_AccountSecureKeyAuthEntity_UniqueId",
                table: "AccountSecureKeyAuth",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UX_AccountSecureKeyAuth_Account_Primary",
                table: "AccountSecureKeyAuth",
                columns: new[] { "AccountId", "IsPrimary" },
                unique: true,
                filter: "IsDeleted = 0 AND IsPrimary = 1");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogEntity_CreatedAt",
                table: "VerificationLogs",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogEntity_UpdatedAt",
                table: "VerificationLogs",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogs_AccountId",
                table: "VerificationLogs",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogs_DeviceId",
                table: "VerificationLogs",
                column: "DeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogs_Membership",
                table: "VerificationLogs",
                column: "MembershipId",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogs_Membership_Purpose",
                table: "VerificationLogs",
                columns: new[] { "MembershipId", "Purpose" },
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogs_MobileNumberId",
                table: "VerificationLogs",
                column: "MobileNumberId");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogs_VerifiedAt",
                table: "VerificationLogs",
                column: "VerifiedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "UQ_VerificationLogEntity_UniqueId",
                table: "VerificationLogs",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AccountSecureKeyAuth_Primary_Fast",
                table: "AccountSecureKeyAuth",
                columns: new[] { "AccountId", "IsPrimary", "IsEnabled" },
                filter: "IsDeleted = 0 AND IsPrimary = 1")
                .Annotation("SqlServer:Include", new[] { "SecureKey", "MaskingKey", "CredentialsVersion", "UniqueId" });

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_Membership_Default",
                table: "Accounts",
                columns: new[] { "MembershipId", "IsDefaultAccount" },
                filter: "IsDeleted = 0 AND IsDefaultAccount = 1")
                .Annotation("SqlServer:Include", new[] { "UniqueId" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_Membership_Device",
                table: "DeviceContexts",
                columns: new[] { "MembershipId", "DeviceId" },
                filter: "IsDeleted = 0 AND ActiveAccountId IS NOT NULL")
                .Annotation("SqlServer:Include", new[] { "ActiveAccountId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_DeviceContexts_Membership_Device",
                table: "DeviceContexts");

            migrationBuilder.DropIndex(
                name: "IX_Accounts_Membership_Default",
                table: "Accounts");

            migrationBuilder.DropTable(
                name: "AccountPinAuth");

            migrationBuilder.DropTable(
                name: "AccountSecureKeyAuth");

            migrationBuilder.DropTable(
                name: "VerificationLogs");

            migrationBuilder.DropIndex(
                name: "IX_Memberships_Login_Covering",
                table: "Memberships");

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedBy",
                table: "VerificationFlows",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "VerificationFlows",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeletedBy",
                table: "VerificationFlows",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "UpdatedBy",
                table: "VerificationFlows",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedBy",
                table: "OtpCodes",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "OtpCodes",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeletedBy",
                table: "OtpCodes",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "UpdatedBy",
                table: "OtpCodes",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedBy",
                table: "MobileNumbers",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "MobileNumbers",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeletedBy",
                table: "MobileNumbers",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "UpdatedBy",
                table: "MobileNumbers",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedBy",
                table: "Memberships",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "CredentialsVersion",
                table: "Memberships",
                type: "int",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "Memberships",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeletedBy",
                table: "Memberships",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "MaskingKey",
                table: "Memberships",
                type: "VARBINARY(32)",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "SecureKey",
                table: "Memberships",
                type: "VARBINARY(176)",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "UpdatedBy",
                table: "Memberships",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedBy",
                table: "MasterKeyShares",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "MasterKeyShares",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeletedBy",
                table: "MasterKeyShares",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "UpdatedBy",
                table: "MasterKeyShares",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedBy",
                table: "LogoutAudits",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "LogoutAudits",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeletedBy",
                table: "LogoutAudits",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "UpdatedBy",
                table: "LogoutAudits",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedBy",
                table: "LoginAttempts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "LoginAttempts",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeletedBy",
                table: "LoginAttempts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "UpdatedBy",
                table: "LoginAttempts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedBy",
                table: "FailedOtpAttempts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "FailedOtpAttempts",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeletedBy",
                table: "FailedOtpAttempts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "UpdatedBy",
                table: "FailedOtpAttempts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedBy",
                table: "Devices",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "Devices",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeletedBy",
                table: "Devices",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "UpdatedBy",
                table: "Devices",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedBy",
                table: "DeviceContexts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "DeviceContexts",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeletedBy",
                table: "DeviceContexts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "UpdatedBy",
                table: "DeviceContexts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedBy",
                table: "Accounts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "CredentialsVersion",
                table: "Accounts",
                type: "int",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "Accounts",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeletedBy",
                table: "Accounts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "MaskingKey",
                table: "Accounts",
                type: "VARBINARY(32)",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "SecureKey",
                table: "Accounts",
                type: "VARBINARY(176)",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "UpdatedBy",
                table: "Accounts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Memberships_Login_Covering",
                table: "Memberships",
                column: "MobileNumberId",
                filter: "IsDeleted = 0 AND Status = 'active'")
                .Annotation("SqlServer:Include", new[] { "UniqueId", "SecureKey", "MaskingKey", "CredentialsVersion", "CreationStatus" });

            migrationBuilder.AddCheckConstraint(
                name: "CHK_Memberships_Credentials_Consistency",
                table: "Memberships",
                sql: "(SecureKey IS NULL AND MaskingKey IS NULL) OR (SecureKey IS NOT NULL AND MaskingKey IS NOT NULL)");
        }
    }
}
