using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Ecliptix.IdentityAccess.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class FixNamingConventions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MembershipRelations");

            migrationBuilder.RenameTable(
                name: "Memberships",
                newName: "memberships");

            migrationBuilder.RenameTable(
                name: "Devices",
                newName: "devices");

            migrationBuilder.RenameTable(
                name: "Accounts",
                newName: "accounts");

            migrationBuilder.RenameTable(
                name: "VerificationLogs",
                newName: "verification_logs");

            migrationBuilder.RenameTable(
                name: "VerificationFlows",
                newName: "verification_flows");

            migrationBuilder.RenameTable(
                name: "OtpCodes",
                newName: "otp_codes");

            migrationBuilder.RenameTable(
                name: "MobileNumbers",
                newName: "mobile_numbers");

            migrationBuilder.RenameTable(
                name: "MasterKeyShares",
                newName: "master_key_shares");

            migrationBuilder.RenameTable(
                name: "LogoutAudits",
                newName: "logout_audits");

            migrationBuilder.RenameTable(
                name: "LoginAttempts",
                newName: "login_attempts");

            migrationBuilder.RenameTable(
                name: "FailedOtpAttempts",
                newName: "failed_otp_attempts");

            migrationBuilder.RenameTable(
                name: "DeviceContexts",
                newName: "device_contexts");

            migrationBuilder.RenameTable(
                name: "AccountSecureKeyAuth",
                newName: "account_secure_key_auth");

            migrationBuilder.RenameTable(
                name: "AccountProfiles",
                newName: "account_profiles");

            migrationBuilder.RenameTable(
                name: "AccountPinAuth",
                newName: "account_pin_auth");

            migrationBuilder.RenameColumn(
                name: "app_device_id",
                table: "memberships",
                newName: "device_id");

            migrationBuilder.RenameIndex(
                name: "IX_Memberships_AppDeviceId",
                table: "memberships",
                newName: "IX_Memberships_DeviceId");

            migrationBuilder.RenameColumn(
                name: "app_device_id",
                table: "verification_flows",
                newName: "device_id");

            migrationBuilder.RenameIndex(
                name: "IX_VerificationFlows_AppDeviceId",
                table: "verification_flows",
                newName: "IX_VerificationFlows_DeviceId");

            migrationBuilder.RenameColumn(
                name: "account_unique_id",
                table: "master_key_shares",
                newName: "account_id");

            migrationBuilder.RenameColumn(
                name: "membership_unique_id",
                table: "logout_audits",
                newName: "membership_id");

            migrationBuilder.RenameColumn(
                name: "membership_unique_id",
                table: "login_attempts",
                newName: "membership_id");

            migrationBuilder.RenameColumn(
                name: "otp_record_id",
                table: "failed_otp_attempts",
                newName: "otp_code_id");

            migrationBuilder.RenameIndex(
                name: "IX_FailedOtpAttempts_OtpRecordId",
                table: "failed_otp_attempts",
                newName: "IX_FailedOtpAttempts_OtpCodeId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameTable(
                name: "memberships",
                newName: "Memberships");

            migrationBuilder.RenameTable(
                name: "devices",
                newName: "Devices");

            migrationBuilder.RenameTable(
                name: "accounts",
                newName: "Accounts");

            migrationBuilder.RenameTable(
                name: "verification_logs",
                newName: "VerificationLogs");

            migrationBuilder.RenameTable(
                name: "verification_flows",
                newName: "VerificationFlows");

            migrationBuilder.RenameTable(
                name: "otp_codes",
                newName: "OtpCodes");

            migrationBuilder.RenameTable(
                name: "mobile_numbers",
                newName: "MobileNumbers");

            migrationBuilder.RenameTable(
                name: "master_key_shares",
                newName: "MasterKeyShares");

            migrationBuilder.RenameTable(
                name: "logout_audits",
                newName: "LogoutAudits");

            migrationBuilder.RenameTable(
                name: "login_attempts",
                newName: "LoginAttempts");

            migrationBuilder.RenameTable(
                name: "failed_otp_attempts",
                newName: "FailedOtpAttempts");

            migrationBuilder.RenameTable(
                name: "device_contexts",
                newName: "DeviceContexts");

            migrationBuilder.RenameTable(
                name: "account_secure_key_auth",
                newName: "AccountSecureKeyAuth");

            migrationBuilder.RenameTable(
                name: "account_profiles",
                newName: "AccountProfiles");

            migrationBuilder.RenameTable(
                name: "account_pin_auth",
                newName: "AccountPinAuth");

            migrationBuilder.RenameColumn(
                name: "device_id",
                table: "Memberships",
                newName: "app_device_id");

            migrationBuilder.RenameIndex(
                name: "IX_Memberships_DeviceId",
                table: "Memberships",
                newName: "IX_Memberships_AppDeviceId");

            migrationBuilder.RenameColumn(
                name: "device_id",
                table: "VerificationFlows",
                newName: "app_device_id");

            migrationBuilder.RenameIndex(
                name: "IX_VerificationFlows_DeviceId",
                table: "VerificationFlows",
                newName: "IX_VerificationFlows_AppDeviceId");

            migrationBuilder.RenameColumn(
                name: "account_id",
                table: "MasterKeyShares",
                newName: "account_unique_id");

            migrationBuilder.RenameColumn(
                name: "membership_id",
                table: "LogoutAudits",
                newName: "membership_unique_id");

            migrationBuilder.RenameColumn(
                name: "membership_id",
                table: "LoginAttempts",
                newName: "membership_unique_id");

            migrationBuilder.RenameColumn(
                name: "otp_code_id",
                table: "FailedOtpAttempts",
                newName: "otp_record_id");

            migrationBuilder.RenameIndex(
                name: "IX_FailedOtpAttempts_OtpCodeId",
                table: "FailedOtpAttempts",
                newName: "IX_FailedOtpAttempts_OtpRecordId");

            migrationBuilder.CreateTable(
                name: "MembershipRelations",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    initiator_account_id = table.Column<long>(type: "bigint", nullable: false),
                    recipient_account_id = table.Column<long>(type: "bigint", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    message = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    meta_json = table.Column<string>(type: "text", nullable: true),
                    muted_until = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false, defaultValue: new byte[] { 0 }),
                    status = table.Column<string>(type: "text", nullable: true),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_membership_relations", x => x.id);
                    table.ForeignKey(
                        name: "fk_membership_relations_accounts_initiator_account_id",
                        column: x => x.initiator_account_id,
                        principalTable: "Accounts",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_membership_relations_accounts_recipient_account_id",
                        column: x => x.recipient_account_id,
                        principalTable: "Accounts",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_MembershipRelations_InitiatorRecipient",
                table: "MembershipRelations",
                columns: new[] { "initiator_account_id", "recipient_account_id" },
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_MembershipRelations_RecipientInitiator",
                table: "MembershipRelations",
                columns: new[] { "recipient_account_id", "initiator_account_id" },
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "UQ_MembershipRelationEntity_UniqueId",
                table: "MembershipRelations",
                column: "unique_id",
                unique: true);
        }
    }
}
