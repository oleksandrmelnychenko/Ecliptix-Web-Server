using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Ecliptix.IdentityAccess.Infrastructure.Migrations
{

    public partial class InitialPostgreSQLMigration : Migration
    {

        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Devices",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    app_instance_id = table.Column<Guid>(type: "uuid", nullable: false),
                    device_id = table.Column<Guid>(type: "uuid", nullable: false),
                    device_type = table.Column<int>(type: "integer", nullable: false, defaultValue: 1),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_devices", x => x.id);
                    table.UniqueConstraint("ak_devices_device_id", x => x.device_id);
                });

            migrationBuilder.CreateTable(
                name: "MobileNumbers",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    number = table.Column<string>(type: "character varying(18)", maxLength: 18, nullable: false),
                    region = table.Column<string>(type: "character varying(2)", maxLength: 2, nullable: true),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_mobile_numbers", x => x.id);
                    table.UniqueConstraint("ak_mobile_numbers_unique_id", x => x.unique_id);
                });

            migrationBuilder.CreateTable(
                name: "VerificationFlows",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    mobile_number_id = table.Column<Guid>(type: "uuid", nullable: false),
                    app_device_id = table.Column<Guid>(type: "uuid", nullable: false),
                    status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false, defaultValue: "pending"),
                    purpose = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false, defaultValue: "unspecified"),
                    otp_count = table.Column<short>(type: "smallint", nullable: false, defaultValue: (short)0),
                    connection_id = table.Column<long>(type: "bigint", nullable: true),
                    last_otp_sent_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    resend_available_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_verification_flows", x => x.id);
                    table.UniqueConstraint("ak_verification_flows_unique_id", x => x.unique_id);
                    table.CheckConstraint("CHK_VerificationFlows_Purpose", "purpose IN ('unspecified', 'registration', 'login', 'password_recovery', 'update_phone')");
                    table.CheckConstraint("CHK_VerificationFlows_Status", "status IN ('pending', 'verified', 'expired', 'failed')");
                    table.ForeignKey(
                        name: "FK_VerificationFlows_Devices",
                        column: x => x.app_device_id,
                        principalTable: "Devices",
                        principalColumn: "device_id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_VerificationFlows_MobileNumbers",
                        column: x => x.mobile_number_id,
                        principalTable: "MobileNumbers",
                        principalColumn: "unique_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Memberships",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    mobile_number_id = table.Column<Guid>(type: "uuid", nullable: false),
                    app_device_id = table.Column<Guid>(type: "uuid", nullable: false),
                    verification_flow_id = table.Column<Guid>(type: "uuid", nullable: true),
                    status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false, defaultValue: "inactive"),
                    creation_status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_memberships", x => x.id);
                    table.UniqueConstraint("ak_memberships_unique_id", x => x.unique_id);
                    table.CheckConstraint("CHK_Memberships_CreationStatus", "creation_status IN ('otp_verified', 'secure_key_set', 'passphrase_set')");
                    table.CheckConstraint("CHK_Memberships_Status", "status IN ('active', 'inactive')");
                    table.ForeignKey(
                        name: "FK_Memberships_Devices",
                        column: x => x.app_device_id,
                        principalTable: "Devices",
                        principalColumn: "device_id");
                    table.ForeignKey(
                        name: "FK_Memberships_MobileNumbers",
                        column: x => x.mobile_number_id,
                        principalTable: "MobileNumbers",
                        principalColumn: "unique_id");
                    table.ForeignKey(
                        name: "FK_Memberships_VerificationFlows",
                        column: x => x.verification_flow_id,
                        principalTable: "VerificationFlows",
                        principalColumn: "unique_id");
                });

            migrationBuilder.CreateTable(
                name: "OtpCodes",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    verification_flow_id = table.Column<long>(type: "bigint", nullable: false),
                    otp_value = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    otp_salt = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false, defaultValue: "active"),
                    attempt_count = table.Column<short>(type: "smallint", nullable: false, defaultValue: (short)0),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    verified_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_otp_codes", x => x.id);
                    table.CheckConstraint("CHK_OtpCodes_Status", "status IN ('active', 'used', 'expired', 'invalid')");
                    table.ForeignKey(
                        name: "FK_OtpCodes_VerificationFlows",
                        column: x => x.verification_flow_id,
                        principalTable: "VerificationFlows",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Accounts",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    membership_id = table.Column<Guid>(type: "uuid", nullable: false),
                    account_type = table.Column<int>(type: "integer", nullable: false),
                    status = table.Column<int>(type: "integer", nullable: false),
                    is_default_account = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    preferred_language = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: true),
                    time_zone_id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    country_code = table.Column<string>(type: "character varying(2)", maxLength: 2, nullable: true),
                    data_residency_region = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    last_accessed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_accounts", x => x.id);
                    table.UniqueConstraint("ak_accounts_unique_id", x => x.unique_id);
                    table.CheckConstraint("CHK_Accounts_Default_Active", "(is_default_account = false) OR (status != 2)");
                    table.ForeignKey(
                        name: "FK_Accounts_Memberships",
                        column: x => x.membership_id,
                        principalTable: "Memberships",
                        principalColumn: "unique_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MasterKeyShares",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    membership_unique_id = table.Column<Guid>(type: "uuid", nullable: false),
                    share_index = table.Column<int>(type: "integer", nullable: false),
                    encrypted_share = table.Column<byte[]>(type: "bytea", nullable: false),
                    share_metadata = table.Column<string>(type: "varchar(500)", nullable: false),
                    storage_location = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    credentials_version = table.Column<int>(type: "integer", nullable: false, defaultValue: 1),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_master_key_shares", x => x.id);
                    table.ForeignKey(
                        name: "FK_MasterKeyShares_Memberships",
                        column: x => x.membership_unique_id,
                        principalTable: "Memberships",
                        principalColumn: "unique_id");
                });

            migrationBuilder.CreateTable(
                name: "FailedOtpAttempts",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    otp_record_id = table.Column<long>(type: "bigint", nullable: false),
                    attempted_value = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    failure_reason = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    attempted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_failed_otp_attempts", x => x.id);
                    table.ForeignKey(
                        name: "FK_FailedOtpAttempts_OtpCodes",
                        column: x => x.otp_record_id,
                        principalTable: "OtpCodes",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AccountPinAuth",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    account_id = table.Column<Guid>(type: "uuid", nullable: false),
                    device_id = table.Column<Guid>(type: "uuid", nullable: true),
                    secure_key = table.Column<byte[]>(type: "bytea", maxLength: 176, nullable: false),
                    masking_key = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    credentials_version = table.Column<int>(type: "integer", nullable: false, defaultValue: 1),
                    is_primary = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    is_enabled = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    is_device_specific = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    pin_length = table.Column<int>(type: "integer", nullable: false, defaultValue: 6),
                    last_used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    failed_attempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    locked_until = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_account_pin_auth", x => x.id);
                    table.ForeignKey(
                        name: "FK_AccountPinAuth_Accounts",
                        column: x => x.account_id,
                        principalTable: "Accounts",
                        principalColumn: "unique_id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AccountPinAuth_Devices",
                        column: x => x.device_id,
                        principalTable: "Devices",
                        principalColumn: "device_id");
                });

            migrationBuilder.CreateTable(
                name: "AccountProfiles",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    account_id = table.Column<Guid>(type: "uuid", nullable: false),
                    profile_name = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    display_name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_account_profiles", x => x.id);
                    table.ForeignKey(
                        name: "FK_AccountProfiles_Accounts",
                        column: x => x.account_id,
                        principalTable: "Accounts",
                        principalColumn: "unique_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AccountSecureKeyAuth",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    account_id = table.Column<Guid>(type: "uuid", nullable: false),
                    secure_key = table.Column<byte[]>(type: "bytea", maxLength: 240, nullable: false),
                    masking_key = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    credentials_version = table.Column<int>(type: "integer", nullable: false, defaultValue: 1),
                    is_primary = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    is_enabled = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    last_used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    failed_attempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    locked_until = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_account_secure_key_auth", x => x.id);
                    table.ForeignKey(
                        name: "FK_AccountSecureKeyAuth_Accounts",
                        column: x => x.account_id,
                        principalTable: "Accounts",
                        principalColumn: "unique_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeviceContexts",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    membership_id = table.Column<Guid>(type: "uuid", nullable: false),
                    device_id = table.Column<Guid>(type: "uuid", nullable: false),
                    active_account_id = table.Column<Guid>(type: "uuid", nullable: true),
                    is_active = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    context_established_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    context_expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_activity_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    device_entity_id = table.Column<long>(type: "bigint", nullable: true),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_device_contexts", x => x.id);
                    table.CheckConstraint("CHK_DeviceContexts_Activity_Valid", "last_activity_at IS NULL OR last_activity_at >= context_established_at");
                    table.CheckConstraint("CHK_DeviceContexts_Expiry_Future", "context_expires_at > context_established_at");
                    table.ForeignKey(
                        name: "FK_DeviceContexts_Accounts",
                        column: x => x.active_account_id,
                        principalTable: "Accounts",
                        principalColumn: "unique_id");
                    table.ForeignKey(
                        name: "FK_DeviceContexts_Devices",
                        column: x => x.device_id,
                        principalTable: "Devices",
                        principalColumn: "device_id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_DeviceContexts_Memberships",
                        column: x => x.membership_id,
                        principalTable: "Memberships",
                        principalColumn: "unique_id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_device_contexts_devices_device_entity_id",
                        column: x => x.device_entity_id,
                        principalTable: "Devices",
                        principalColumn: "id");
                });

            migrationBuilder.CreateTable(
                name: "LoginAttempts",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    membership_unique_id = table.Column<Guid>(type: "uuid", nullable: true),
                    account_id = table.Column<Guid>(type: "uuid", nullable: true),
                    device_id = table.Column<Guid>(type: "uuid", nullable: true),
                    mobile_number = table.Column<string>(type: "character varying(18)", maxLength: 18, nullable: true),
                    outcome = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    is_success = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    error_message = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    ip_address = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    platform = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    attempted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    completed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    locked_until = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_login_attempts", x => x.id);
                    table.CheckConstraint("CHK_LoginAttempts_LockedUntil_Future", "locked_until IS NULL OR locked_until > attempted_at");
                    table.CheckConstraint("CHK_LoginAttempts_Success_CompletedAt", "(is_success = false) OR (completed_at IS NOT NULL)");
                    table.ForeignKey(
                        name: "FK_LoginAttempts_Accounts",
                        column: x => x.account_id,
                        principalTable: "Accounts",
                        principalColumn: "unique_id");
                    table.ForeignKey(
                        name: "FK_LoginAttempts_Devices",
                        column: x => x.device_id,
                        principalTable: "Devices",
                        principalColumn: "device_id");
                    table.ForeignKey(
                        name: "FK_LoginAttempts_Memberships",
                        column: x => x.membership_unique_id,
                        principalTable: "Memberships",
                        principalColumn: "unique_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "LogoutAudits",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    membership_unique_id = table.Column<Guid>(type: "uuid", nullable: false),
                    account_id = table.Column<Guid>(type: "uuid", nullable: true),
                    device_id = table.Column<Guid>(type: "uuid", nullable: true),
                    reason = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ip_address = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    platform = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    logged_out_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_logout_audits", x => x.id);
                    table.ForeignKey(
                        name: "FK_LogoutAudits_Accounts",
                        column: x => x.account_id,
                        principalTable: "Accounts",
                        principalColumn: "unique_id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_LogoutAudits_Memberships",
                        column: x => x.membership_unique_id,
                        principalTable: "Memberships",
                        principalColumn: "unique_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MembershipRelations",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    initiator_account_id = table.Column<long>(type: "bigint", nullable: false),
                    recipient_account_id = table.Column<long>(type: "bigint", nullable: false),
                    status = table.Column<string>(type: "text", nullable: true),
                    message = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    meta_json = table.Column<string>(type: "text", nullable: true),
                    muted_until = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
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

            migrationBuilder.CreateTable(
                name: "VerificationLogs",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    membership_id = table.Column<Guid>(type: "uuid", nullable: false),
                    mobile_number_id = table.Column<Guid>(type: "uuid", nullable: false),
                    device_id = table.Column<Guid>(type: "uuid", nullable: false),
                    account_id = table.Column<Guid>(type: "uuid", nullable: true),
                    purpose = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    otp_count = table.Column<short>(type: "smallint", nullable: false, defaultValue: (short)0),
                    verified_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_verification_logs", x => x.id);
                    table.ForeignKey(
                        name: "FK_VerificationLogs_Accounts",
                        column: x => x.account_id,
                        principalTable: "Accounts",
                        principalColumn: "unique_id");
                    table.ForeignKey(
                        name: "FK_VerificationLogs_Devices",
                        column: x => x.device_id,
                        principalTable: "Devices",
                        principalColumn: "device_id");
                    table.ForeignKey(
                        name: "FK_VerificationLogs_Memberships",
                        column: x => x.membership_id,
                        principalTable: "Memberships",
                        principalColumn: "unique_id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_VerificationLogs_MobileNumbers",
                        column: x => x.mobile_number_id,
                        principalTable: "MobileNumbers",
                        principalColumn: "unique_id");
                });

            migrationBuilder.CreateIndex(
                name: "ix_account_pin_auth_device_id",
                table: "AccountPinAuth",
                column: "device_id");

            migrationBuilder.CreateIndex(
                name: "IX_AccountPinAuth_Account_Enabled",
                table: "AccountPinAuth",
                column: "account_id",
                filter: "is_deleted = false AND is_enabled = true");

            migrationBuilder.CreateIndex(
                name: "IX_AccountPinAuth_Covering",
                table: "AccountPinAuth",
                columns: new[] { "account_id", "device_id" },
                unique: true,
                filter: "is_deleted = false AND is_enabled = true");

            migrationBuilder.CreateIndex(
                name: "UQ_AccountPinAuthEntity_UniqueId",
                table: "AccountPinAuth",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AccountProfiles_AccountId_Unique",
                table: "AccountProfiles",
                column: "account_id",
                unique: true,
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_AccountProfiles_ProfileName_Covering",
                table: "AccountProfiles",
                column: "profile_name",
                unique: true,
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "UQ_AccountProfileEntity_UniqueId",
                table: "AccountProfiles",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_accounts_membership_id",
                table: "Accounts",
                column: "membership_id",
                filter: "is_deleted = false AND status = 1");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_Membership_Type",
                table: "Accounts",
                columns: new[] { "membership_id", "account_type" },
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_Status",
                table: "Accounts",
                column: "status",
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "UQ_AccountEntity_UniqueId",
                table: "Accounts",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UX_Accounts_Membership_Default",
                table: "Accounts",
                columns: new[] { "membership_id", "is_default_account" },
                unique: true,
                filter: "is_deleted = false AND is_default_account = true");

            migrationBuilder.CreateIndex(
                name: "IX_AccountSecureKeyAuth_Account_Enabled",
                table: "AccountSecureKeyAuth",
                column: "account_id",
                filter: "is_deleted = false AND is_enabled = true");

            migrationBuilder.CreateIndex(
                name: "UQ_AccountSecureKeyAuthEntity_UniqueId",
                table: "AccountSecureKeyAuth",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UX_AccountSecureKeyAuth_Account_Primary",
                table: "AccountSecureKeyAuth",
                columns: new[] { "account_id", "is_primary" },
                unique: true,
                filter: "is_deleted = false AND is_primary = true");

            migrationBuilder.CreateIndex(
                name: "ix_device_contexts_active_account_id",
                table: "DeviceContexts",
                column: "active_account_id");

            migrationBuilder.CreateIndex(
                name: "ix_device_contexts_device_entity_id",
                table: "DeviceContexts",
                column: "device_entity_id");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_Active_Covering",
                table: "DeviceContexts",
                columns: new[] { "membership_id", "device_id" },
                filter: "is_deleted = false AND is_active = true");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_DeviceId_Active",
                table: "DeviceContexts",
                column: "device_id",
                filter: "is_deleted = false AND is_active = true");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_ExpiresAt",
                table: "DeviceContexts",
                column: "context_expires_at",
                filter: "is_deleted = false AND is_active = true");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_ExpiresAt_Cleanup",
                table: "DeviceContexts",
                columns: new[] { "context_expires_at", "is_active" },
                filter: "is_deleted = false AND is_active = true");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_Membership_IsActive",
                table: "DeviceContexts",
                columns: new[] { "membership_id", "is_active" },
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_DeviceContexts_MembershipActivity",
                table: "DeviceContexts",
                columns: new[] { "membership_id", "last_activity_at" },
                descending: new[] { false, true },
                filter: "is_deleted = false AND is_active = true");

            migrationBuilder.CreateIndex(
                name: "UQ_DeviceContextEntity_UniqueId",
                table: "DeviceContexts",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UX_DeviceContexts_Membership_Device_Active",
                table: "DeviceContexts",
                columns: new[] { "membership_id", "device_id", "is_active" },
                unique: true,
                filter: "is_deleted = false AND is_active = true");

            migrationBuilder.CreateIndex(
                name: "IX_Devices_AppInstanceId",
                table: "Devices",
                column: "app_instance_id",
                unique: true,
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_Devices_DeviceId",
                table: "Devices",
                column: "device_id",
                unique: true,
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_Devices_DeviceType",
                table: "Devices",
                column: "device_type",
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "UQ_DeviceEntity_UniqueId",
                table: "Devices",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_FailedOtpAttempts_AttemptedAt",
                table: "FailedOtpAttempts",
                column: "attempted_at",
                descending: new bool[0],
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_FailedOtpAttempts_OtpRecordId",
                table: "FailedOtpAttempts",
                column: "otp_record_id");

            migrationBuilder.CreateIndex(
                name: "UQ_FailedOtpAttemptEntity_UniqueId",
                table: "FailedOtpAttempts",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_login_attempts_account_id",
                table: "LoginAttempts",
                column: "account_id");

            migrationBuilder.CreateIndex(
                name: "ix_login_attempts_device_id_attempted_at",
                table: "LoginAttempts",
                columns: new[] { "device_id", "attempted_at" },
                descending: new[] { false, true },
                filter: "is_deleted = false AND device_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_login_attempts_mobile_number_locked_until_attempted_at",
                table: "LoginAttempts",
                columns: new[] { "mobile_number", "locked_until", "attempted_at" },
                descending: new[] { false, false, true },
                filter: "is_deleted = false AND locked_until IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_CountFailed",
                table: "LoginAttempts",
                columns: new[] { "mobile_number", "attempted_at", "is_success" },
                filter: "is_deleted = false AND is_success = false AND locked_until IS NULL");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_MembershipCreation",
                table: "LoginAttempts",
                columns: new[] { "membership_unique_id", "outcome", "attempted_at" },
                filter: "is_deleted = false AND is_success = false AND outcome = 'membership_creation'");

            migrationBuilder.CreateIndex(
                name: "UQ_LoginAttemptEntity_UniqueId",
                table: "LoginAttempts",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_logout_audits_account_id",
                table: "LogoutAudits",
                column: "account_id");

            migrationBuilder.CreateIndex(
                name: "IX_LogoutAudits_DeviceId",
                table: "LogoutAudits",
                column: "device_id",
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_LogoutAudits_LoggedOutAt",
                table: "LogoutAudits",
                column: "logged_out_at",
                descending: new bool[0],
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_LogoutAudits_Membership_LoggedOutAt",
                table: "LogoutAudits",
                columns: new[] { "membership_unique_id", "logged_out_at" },
                descending: new[] { false, true },
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "UQ_LogoutAuditEntity_UniqueId",
                table: "LogoutAudits",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MasterKeyShares_ShareIndex",
                table: "MasterKeyShares",
                column: "share_index");

            migrationBuilder.CreateIndex(
                name: "UQ_MasterKeyShareEntity_UniqueId",
                table: "MasterKeyShares",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UQ_MasterKeyShares_MembershipShare",
                table: "MasterKeyShares",
                columns: new[] { "membership_unique_id", "share_index" },
                unique: true);

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

            migrationBuilder.CreateIndex(
                name: "IX_Memberships_AppDeviceId",
                table: "Memberships",
                column: "app_device_id");

            migrationBuilder.CreateIndex(
                name: "IX_Memberships_Status",
                table: "Memberships",
                column: "status",
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "ix_memberships_verification_flow_id",
                table: "Memberships",
                column: "verification_flow_id");

            migrationBuilder.CreateIndex(
                name: "UQ_Memberships_ActiveMembership",
                table: "Memberships",
                column: "mobile_number_id",
                unique: true,
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "UQ_Memberships_UniqueId",
                table: "Memberships",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MobileNumbers_CreatedAt",
                table: "MobileNumbers",
                column: "created_at",
                descending: new bool[0],
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_MobileNumbers_MobileNumber_Region",
                table: "MobileNumbers",
                columns: new[] { "number", "region" },
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_MobileNumbers_Region",
                table: "MobileNumbers",
                column: "region",
                filter: "is_deleted = false AND Region IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "UQ_MobileNumberEntity_UniqueId",
                table: "MobileNumbers",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UQ_MobileNumbers_ActiveNumberRegion",
                table: "MobileNumbers",
                columns: new[] { "number", "region", "is_deleted" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UQ_MobileNumbers_Number",
                table: "MobileNumbers",
                column: "number",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OtpCodes_ExpiresAt",
                table: "OtpCodes",
                column: "expires_at",
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_OtpCodes_Status",
                table: "OtpCodes",
                column: "status",
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_OtpCodes_VerificationFlowId",
                table: "OtpCodes",
                column: "verification_flow_id");

            migrationBuilder.CreateIndex(
                name: "UQ_OtpCodeEntity_UniqueId",
                table: "OtpCodes",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlows_AppDeviceId",
                table: "VerificationFlows",
                column: "app_device_id");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlows_CooldownCheck",
                table: "VerificationFlows",
                columns: new[] { "unique_id", "last_otp_sent_at", "otp_count", "expires_at" },
                filter: "is_deleted = false AND status = 'pending'");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlows_ExpiresAt",
                table: "VerificationFlows",
                column: "expires_at",
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlows_MobileNumberId",
                table: "VerificationFlows",
                column: "mobile_number_id");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlows_Status",
                table: "VerificationFlows",
                column: "status",
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "UQ_VerificationFlowEntity_UniqueId",
                table: "VerificationFlows",
                column: "unique_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_verification_logs_account_id",
                table: "VerificationLogs",
                column: "account_id");

            migrationBuilder.CreateIndex(
                name: "ix_verification_logs_mobile_number_id",
                table: "VerificationLogs",
                column: "mobile_number_id");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogs_DeviceId",
                table: "VerificationLogs",
                column: "device_id",
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogs_Membership",
                table: "VerificationLogs",
                column: "membership_id",
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogs_Membership_Purpose",
                table: "VerificationLogs",
                columns: new[] { "membership_id", "purpose" },
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogs_VerifiedAt",
                table: "VerificationLogs",
                column: "verified_at",
                descending: new bool[0],
                filter: "is_deleted = false");

            migrationBuilder.CreateIndex(
                name: "UQ_VerificationLogEntity_UniqueId",
                table: "VerificationLogs",
                column: "unique_id",
                unique: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AccountPinAuth");

            migrationBuilder.DropTable(
                name: "AccountProfiles");

            migrationBuilder.DropTable(
                name: "AccountSecureKeyAuth");

            migrationBuilder.DropTable(
                name: "DeviceContexts");

            migrationBuilder.DropTable(
                name: "FailedOtpAttempts");

            migrationBuilder.DropTable(
                name: "LoginAttempts");

            migrationBuilder.DropTable(
                name: "LogoutAudits");

            migrationBuilder.DropTable(
                name: "MasterKeyShares");

            migrationBuilder.DropTable(
                name: "MembershipRelations");

            migrationBuilder.DropTable(
                name: "VerificationLogs");

            migrationBuilder.DropTable(
                name: "OtpCodes");

            migrationBuilder.DropTable(
                name: "Accounts");

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
