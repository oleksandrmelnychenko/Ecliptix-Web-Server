using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    public partial class OptimizeSchemaWorldClass : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
                IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[LoginAttempts_Archive_20251013]') AND type in (N'U'))
                BEGIN
                    SELECT * INTO [LoginAttempts_Archive_20251013]
                    FROM [LoginAttempts]
                    WHERE 1=1;
                END
            ");

            migrationBuilder.Sql(@"
                IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[LogoutAudits_Archive_20251013]') AND type in (N'U'))
                BEGIN
                    SELECT * INTO [LogoutAudits_Archive_20251013]
                    FROM [LogoutAudits]
                    WHERE 1=1;
                END
            ");

            migrationBuilder.Sql("DELETE FROM [LoginAttempts];");
            migrationBuilder.Sql("DELETE FROM [LogoutAudits];");

            migrationBuilder.Sql("ALTER TABLE [Memberships] ALTER COLUMN [VerificationFlowId] uniqueidentifier NULL;");

            migrationBuilder.Sql("UPDATE [Memberships] SET [VerificationFlowId] = NULL WHERE [VerificationFlowId] IS NOT NULL;");

            migrationBuilder.Sql("DELETE FROM [OtpCodes];");

            migrationBuilder.Sql("DELETE FROM [VerificationFlows];");

            migrationBuilder.DropForeignKey(
                name: "FK_VerificationFlows_MobileNumbers",
                table: "VerificationFlows");

            migrationBuilder.Sql("DROP INDEX [IX_VerificationFlows_ActiveFlowRecovery] ON [VerificationFlows];");
            migrationBuilder.Sql("DROP INDEX [IX_VerificationFlows_MobileNumberId] ON [VerificationFlows];");

            migrationBuilder.Sql("ALTER TABLE [VerificationFlows] DROP COLUMN [MobileNumberId];");
            migrationBuilder.Sql("ALTER TABLE [VerificationFlows] ADD [MobileNumberId] uniqueidentifier NOT NULL;");
            migrationBuilder.Sql(@"
                CREATE INDEX [IX_VerificationFlows_ActiveFlowRecovery]
                ON [VerificationFlows] ([MobileNumberId], [AppDeviceId], [Purpose], [Status], [ExpiresAt])
                INCLUDE ([UniqueId], [ConnectionId], [OtpCount], [CreatedAt], [UpdatedAt])
                WHERE IsDeleted = 0 AND Status = 'pending';
            ");
            migrationBuilder.Sql("CREATE INDEX [IX_VerificationFlows_MobileNumberId] ON [VerificationFlows] ([MobileNumberId]);");

            migrationBuilder.DropTable(
                name: "MobileDevices");

            migrationBuilder.DropIndex(
                name: "IX_Memberships_MobileNumberId",
                table: "Memberships");

            migrationBuilder.DropIndex(
                name: "IX_LogoutAudits_ConnectId",
                table: "LogoutAudits");

            migrationBuilder.DropIndex(
                name: "IX_LoginAttempts_RateLimiting",
                table: "LoginAttempts");

            migrationBuilder.DropIndex(
                name: "IX_LoginAttempts_SessionId",
                table: "LoginAttempts");

            migrationBuilder.DropIndex(
                name: "IX_LoginAttempts_Status",
                table: "LoginAttempts");

            migrationBuilder.DropIndex(
                name: "UQ_Devices_DeviceId",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "ConnectId",
                table: "LogoutAudits");

            migrationBuilder.DropColumn(
                name: "SessionId",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "Status",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "SuccessfulAt",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "Timestamp",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "DeviceId",
                table: "Devices");

            migrationBuilder.AlterColumn<Guid>(
                name: "VerificationFlowId",
                table: "Memberships",
                type: "uniqueidentifier",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uniqueidentifier");

            migrationBuilder.AddColumn<Guid>(
                name: "AccountId",
                table: "LogoutAudits",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeviceId",
                table: "LogoutAudits",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<string>(
                name: "IpAddress",
                table: "LogoutAudits",
                type: "nvarchar(45)",
                maxLength: 45,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "AccountId",
                table: "LoginAttempts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "CompletedAt",
                table: "LoginAttempts",
                type: "DATETIME2",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "DeviceId",
                table: "LoginAttempts",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "IpAddress",
                table: "LoginAttempts",
                type: "nvarchar(45)",
                maxLength: 45,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "UserAgent",
                table: "LoginAttempts",
                type: "nvarchar(500)",
                maxLength: 500,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "Accounts",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MembershipId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AccountType = table.Column<int>(type: "int", nullable: false),
                    AccountName = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    SecureKey = table.Column<byte[]>(type: "VARBINARY(176)", nullable: true),
                    MaskingKey = table.Column<byte[]>(type: "VARBINARY(32)", nullable: true),
                    CredentialsVersion = table.Column<int>(type: "int", nullable: false, defaultValue: 1),
                    Status = table.Column<int>(type: "int", nullable: false),
                    IsDefaultAccount = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    PreferredLanguage = table.Column<string>(type: "nvarchar(10)", maxLength: 10, nullable: true),
                    TimeZoneId = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true),
                    CountryCode = table.Column<string>(type: "nvarchar(2)", maxLength: 2, nullable: true),
                    DataResidencyRegion = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                    LastAccessedAt = table.Column<DateTime>(type: "DATETIME2", nullable: true),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Accounts", x => x.Id);
                    table.UniqueConstraint("AK_Accounts_UniqueId", x => x.UniqueId);
                    table.CheckConstraint("CHK_Accounts_Default_Active", "(IsDefaultAccount = 0) OR (Status != 2)");
                    table.ForeignKey(
                        name: "FK_Accounts_Memberships",
                        column: x => x.MembershipId,
                        principalTable: "Memberships",
                        principalColumn: "UniqueId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeviceContexts",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MembershipId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ActiveAccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ContextEstablishedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    ContextExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    LastActivityAt = table.Column<DateTime>(type: "DATETIME2", nullable: true),
                    IsActive = table.Column<bool>(type: "bit", nullable: false, defaultValue: true),
                    DeviceEntityId = table.Column<long>(type: "bigint", nullable: true),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceContexts", x => x.Id);
                    table.CheckConstraint("CHK_DeviceContexts_Activity_Valid", "LastActivityAt IS NULL OR LastActivityAt >= ContextEstablishedAt");
                    table.CheckConstraint("CHK_DeviceContexts_Expiry_Future", "ContextExpiresAt > ContextEstablishedAt");
                    table.ForeignKey(
                        name: "FK_DeviceContexts_Accounts",
                        column: x => x.ActiveAccountId,
                        principalTable: "Accounts",
                        principalColumn: "UniqueId");
                    table.ForeignKey(
                        name: "FK_DeviceContexts_Devices",
                        column: x => x.DeviceId,
                        principalTable: "Devices",
                        principalColumn: "UniqueId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_DeviceContexts_Devices_DeviceEntityId",
                        column: x => x.DeviceEntityId,
                        principalTable: "Devices",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_DeviceContexts_Memberships",
                        column: x => x.MembershipId,
                        principalTable: "Memberships",
                        principalColumn: "UniqueId",
                        onDelete: ReferentialAction.Cascade);
                });

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

            migrationBuilder.CreateIndex(
                name: "IX_LogoutAudits_AccountId",
                table: "LogoutAudits",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_LogoutAudits_DeviceId",
                table: "LogoutAudits",
                column: "DeviceId",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_AccountId",
                table: "LoginAttempts",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_DeviceRateLimiting",
                table: "LoginAttempts",
                columns: new[] { "DeviceId", "AttemptedAt", "IsSuccess" },
                descending: new[] { false, true, false },
                filter: "IsDeleted = 0 AND DeviceId IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_RateLimiting_Optimized",
                table: "LoginAttempts",
                columns: new[] { "MobileNumber", "AttemptedAt", "IsSuccess", "LockedUntil" },
                descending: new[] { false, true, false, false },
                filter: "IsDeleted = 0 AND LockedUntil IS NULL AND MobileNumber IS NOT NULL");

            migrationBuilder.AddCheckConstraint(
                name: "CHK_LoginAttempts_LockedUntil_Future",
                table: "LoginAttempts",
                sql: "LockedUntil IS NULL OR LockedUntil > AttemptedAt");

            migrationBuilder.AddCheckConstraint(
                name: "CHK_LoginAttempts_Success_CompletedAt",
                table: "LoginAttempts",
                sql: "(IsSuccess = 0) OR (CompletedAt IS NOT NULL)");

            migrationBuilder.CreateIndex(
                name: "IX_AccountEntity_CreatedAt",
                table: "Accounts",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_AccountEntity_UpdatedAt",
                table: "Accounts",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_Membership_Active_Covering",
                table: "Accounts",
                column: "MembershipId",
                filter: "IsDeleted = 0 AND Status = 1")
                .Annotation("SqlServer:Include", new[] { "UniqueId", "AccountType", "AccountName", "IsDefaultAccount" });

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_Membership_Type",
                table: "Accounts",
                columns: new[] { "MembershipId", "AccountType" },
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_Status",
                table: "Accounts",
                column: "Status",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "UQ_AccountEntity_UniqueId",
                table: "Accounts",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UX_Accounts_Membership_Default",
                table: "Accounts",
                columns: new[] { "MembershipId", "IsDefaultAccount" },
                unique: true,
                filter: "IsDeleted = 0 AND IsDefaultAccount = 1");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContextEntity_CreatedAt",
                table: "DeviceContexts",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContextEntity_UpdatedAt",
                table: "DeviceContexts",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_Active_Covering",
                table: "DeviceContexts",
                columns: new[] { "MembershipId", "DeviceId" },
                filter: "IsDeleted = 0 AND IsActive = 1")
                .Annotation("SqlServer:Include", new[] { "UniqueId", "ActiveAccountId", "ContextExpiresAt", "LastActivityAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_ActiveAccountId",
                table: "DeviceContexts",
                column: "ActiveAccountId");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_DeviceEntityId",
                table: "DeviceContexts",
                column: "DeviceEntityId");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_DeviceId_Active",
                table: "DeviceContexts",
                column: "DeviceId",
                filter: "IsDeleted = 0 AND IsActive = 1");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_ExpiresAt",
                table: "DeviceContexts",
                column: "ContextExpiresAt",
                filter: "IsDeleted = 0 AND IsActive = 1");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_ExpiresAt_Cleanup",
                table: "DeviceContexts",
                columns: new[] { "ContextExpiresAt", "IsActive" },
                filter: "IsDeleted = 0 AND IsActive = 1");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_Membership_IsActive",
                table: "DeviceContexts",
                columns: new[] { "MembershipId", "IsActive" },
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_MembershipActivity",
                table: "DeviceContexts",
                columns: new[] { "MembershipId", "LastActivityAt" },
                descending: new[] { false, true },
                filter: "IsDeleted = 0 AND IsActive = 1");

            migrationBuilder.CreateIndex(
                name: "UQ_DeviceContextEntity_UniqueId",
                table: "DeviceContexts",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UX_DeviceContexts_Membership_Device_Active",
                table: "DeviceContexts",
                columns: new[] { "MembershipId", "DeviceId", "IsActive" },
                unique: true,
                filter: "IsDeleted = 0 AND IsActive = 1");

            migrationBuilder.AddForeignKey(
                name: "FK_LoginAttempts_Accounts",
                table: "LoginAttempts",
                column: "AccountId",
                principalTable: "Accounts",
                principalColumn: "UniqueId");

            migrationBuilder.AddForeignKey(
                name: "FK_LoginAttempts_Devices",
                table: "LoginAttempts",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "UniqueId");

            migrationBuilder.AddForeignKey(
                name: "FK_LogoutAudits_Accounts",
                table: "LogoutAudits",
                column: "AccountId",
                principalTable: "Accounts",
                principalColumn: "UniqueId",
                onDelete: ReferentialAction.NoAction);

            migrationBuilder.AddForeignKey(
                name: "FK_LogoutAudits_Devices",
                table: "LogoutAudits",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "UniqueId");

            migrationBuilder.AddForeignKey(
                name: "FK_VerificationFlows_MobileNumbers",
                table: "VerificationFlows",
                column: "MobileNumberId",
                principalTable: "MobileNumbers",
                principalColumn: "UniqueId",
                onDelete: ReferentialAction.Cascade);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_LoginAttempts_Accounts",
                table: "LoginAttempts");

            migrationBuilder.DropForeignKey(
                name: "FK_LoginAttempts_Devices",
                table: "LoginAttempts");

            migrationBuilder.DropForeignKey(
                name: "FK_LogoutAudits_Accounts",
                table: "LogoutAudits");

            migrationBuilder.DropForeignKey(
                name: "FK_LogoutAudits_Devices",
                table: "LogoutAudits");

            migrationBuilder.DropForeignKey(
                name: "FK_VerificationFlows_MobileNumbers",
                table: "VerificationFlows");

            migrationBuilder.DropTable(
                name: "DeviceContexts");

            migrationBuilder.DropTable(
                name: "Accounts");

            migrationBuilder.DropIndex(
                name: "IX_Memberships_Login_Covering",
                table: "Memberships");

            migrationBuilder.DropCheckConstraint(
                name: "CHK_Memberships_Credentials_Consistency",
                table: "Memberships");

            migrationBuilder.DropIndex(
                name: "IX_LogoutAudits_AccountId",
                table: "LogoutAudits");

            migrationBuilder.DropIndex(
                name: "IX_LogoutAudits_DeviceId",
                table: "LogoutAudits");

            migrationBuilder.DropIndex(
                name: "IX_LoginAttempts_AccountId",
                table: "LoginAttempts");

            migrationBuilder.DropIndex(
                name: "IX_LoginAttempts_DeviceRateLimiting",
                table: "LoginAttempts");

            migrationBuilder.DropIndex(
                name: "IX_LoginAttempts_RateLimiting_Optimized",
                table: "LoginAttempts");

            migrationBuilder.DropCheckConstraint(
                name: "CHK_LoginAttempts_LockedUntil_Future",
                table: "LoginAttempts");

            migrationBuilder.DropCheckConstraint(
                name: "CHK_LoginAttempts_Success_CompletedAt",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "AccountId",
                table: "LogoutAudits");

            migrationBuilder.DropColumn(
                name: "DeviceId",
                table: "LogoutAudits");

            migrationBuilder.DropColumn(
                name: "IpAddress",
                table: "LogoutAudits");

            migrationBuilder.DropColumn(
                name: "AccountId",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "CompletedAt",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "DeviceId",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "IpAddress",
                table: "LoginAttempts");

            migrationBuilder.DropColumn(
                name: "UserAgent",
                table: "LoginAttempts");

            migrationBuilder.AlterColumn<long>(
                name: "MobileNumberId",
                table: "VerificationFlows",
                type: "bigint",
                nullable: false,
                oldClrType: typeof(Guid),
                oldType: "uniqueidentifier");

            migrationBuilder.AlterColumn<Guid>(
                name: "VerificationFlowId",
                table: "Memberships",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"),
                oldClrType: typeof(Guid),
                oldType: "uniqueidentifier",
                oldNullable: true);

            migrationBuilder.AddColumn<long>(
                name: "ConnectId",
                table: "LogoutAudits",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<string>(
                name: "SessionId",
                table: "LoginAttempts",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Status",
                table: "LoginAttempts",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "SuccessfulAt",
                table: "LoginAttempts",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "Timestamp",
                table: "LoginAttempts",
                type: "datetime2",
                nullable: false,
                defaultValueSql: "GETUTCDATE()");

            migrationBuilder.AddColumn<Guid>(
                name: "DeviceId",
                table: "Devices",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.CreateTable(
                name: "MobileDevices",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    DeviceId = table.Column<long>(type: "bigint", nullable: false),
                    MobileNumberId = table.Column<long>(type: "bigint", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    IsActive = table.Column<bool>(type: "bit", nullable: false, defaultValue: true),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    LastUsedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RelationshipType = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true, defaultValue: "primary"),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()")
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

            migrationBuilder.CreateIndex(
                name: "IX_Memberships_MobileNumberId",
                table: "Memberships",
                column: "MobileNumberId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LogoutAudits_ConnectId",
                table: "LogoutAudits",
                column: "ConnectId",
                filter: "IsDeleted = 0");

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
                name: "UQ_Devices_DeviceId",
                table: "Devices",
                column: "DeviceId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MobileDeviceEntity_CreatedAt",
                table: "MobileDevices",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MobileDeviceEntity_UpdatedAt",
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
                name: "UQ_MobileDeviceEntity_UniqueId",
                table: "MobileDevices",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UQ_MobileDevices_PhoneDevice",
                table: "MobileDevices",
                columns: new[] { "MobileNumberId", "DeviceId" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_VerificationFlows_MobileNumbers",
                table: "VerificationFlows",
                column: "MobileNumberId",
                principalTable: "MobileNumbers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
