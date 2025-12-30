
using System;
using Ecliptix.Domain.Schema;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    [DbContext(typeof(EcliptixSchemaContext))]
    [Migration("20251229110500_AddSecureKeyRecoveryPurpose")]
    partial class AddSecureKeyRecoveryPurpose
    {

        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "10.0.0")
                .HasAnnotation("Relational:MaxIdentifierLength", 63);

            NpgsqlModelBuilderExtensions.UseIdentityByDefaultColumns(modelBuilder);

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.AccountEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<int>("AccountType")
                        .HasColumnType("integer")
                        .HasColumnName("account_type");

                    b.Property<string>("CountryCode")
                        .HasMaxLength(2)
                        .HasColumnType("character varying(2)")
                        .HasColumnName("country_code");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<string>("DataResidencyRegion")
                        .HasMaxLength(50)
                        .HasColumnType("character varying(50)")
                        .HasColumnName("data_residency_region");

                    b.Property<bool>("IsDefaultAccount")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_default_account");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<DateTimeOffset?>("LastAccessedAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("last_accessed_at");

                    b.Property<Guid>("MembershipId")
                        .HasColumnType("uuid")
                        .HasColumnName("membership_id");

                    b.Property<string>("PreferredLanguage")
                        .HasMaxLength(10)
                        .HasColumnType("character varying(10)")
                        .HasColumnName("preferred_language");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<int>("Status")
                        .HasColumnType("integer")
                        .HasColumnName("status");

                    b.Property<string>("TimeZoneId")
                        .HasMaxLength(100)
                        .HasColumnType("character varying(100)")
                        .HasColumnName("time_zone_id");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_accounts");

                    b.HasAlternateKey("UniqueId")
                        .HasName("ak_accounts_unique_id");

                    b.HasIndex("MembershipId")
                        .HasDatabaseName("ix_accounts_membership_id")
                        .HasFilter("is_deleted = false AND status = 1");

                    b.HasIndex("Status")
                        .HasDatabaseName("IX_Accounts_Status")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_AccountEntity_UniqueId");

                    b.HasIndex("MembershipId", "AccountType")
                        .HasDatabaseName("IX_Accounts_Membership_Type")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("MembershipId", "IsDefaultAccount")
                        .IsUnique()
                        .HasDatabaseName("UX_Accounts_Membership_Default")
                        .HasFilter("is_deleted = false AND is_default_account = true");

                    b.ToTable("Accounts", null, t =>
                        {
                            t.HasCheckConstraint("CHK_Accounts_Default_Active", "(is_default_account = false) OR (status != 2)");
                        });
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.AccountPinAuthEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<Guid>("AccountId")
                        .HasColumnType("uuid")
                        .HasColumnName("account_id");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<int>("CredentialsVersion")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer")
                        .HasDefaultValue(1)
                        .HasColumnName("credentials_version");

                    b.Property<Guid?>("DeviceId")
                        .HasColumnType("uuid")
                        .HasColumnName("device_id");

                    b.Property<int>("FailedAttempts")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer")
                        .HasDefaultValue(0)
                        .HasColumnName("failed_attempts");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<bool>("IsDeviceSpecific")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_device_specific");

                    b.Property<bool>("IsEnabled")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(true)
                        .HasColumnName("is_enabled");

                    b.Property<bool>("IsPrimary")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_primary");

                    b.Property<DateTimeOffset?>("LastUsedAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("last_used_at");

                    b.Property<DateTimeOffset?>("LockedUntil")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("locked_until");

                    b.Property<byte[]>("MaskingKey")
                        .IsRequired()
                        .HasMaxLength(32)
                        .HasColumnType("bytea")
                        .HasColumnName("masking_key");

                    b.Property<int>("PinLength")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer")
                        .HasDefaultValue(6)
                        .HasColumnName("pin_length");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<byte[]>("SecureKey")
                        .IsRequired()
                        .HasMaxLength(176)
                        .HasColumnType("bytea")
                        .HasColumnName("secure_key");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_account_pin_auth");

                    b.HasIndex("AccountId")
                        .HasDatabaseName("IX_AccountPinAuth_Account_Enabled")
                        .HasFilter("is_deleted = false AND is_enabled = true");

                    b.HasIndex("DeviceId")
                        .HasDatabaseName("ix_account_pin_auth_device_id");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_AccountPinAuthEntity_UniqueId");

                    b.HasIndex("AccountId", "DeviceId")
                        .IsUnique()
                        .HasDatabaseName("IX_AccountPinAuth_Covering")
                        .HasFilter("is_deleted = false AND is_enabled = true");

                    b.ToTable("AccountPinAuth", (string)null);
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.AccountProfileEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<Guid>("AccountId")
                        .HasColumnType("uuid")
                        .HasColumnName("account_id");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<string>("DisplayName")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("character varying(100)")
                        .HasColumnName("display_name");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<string>("ProfileName")
                        .IsRequired()
                        .HasMaxLength(50)
                        .HasColumnType("character varying(50)")
                        .HasColumnName("profile_name");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_account_profiles");

                    b.HasIndex("AccountId")
                        .IsUnique()
                        .HasDatabaseName("IX_AccountProfiles_AccountId_Unique")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("ProfileName")
                        .IsUnique()
                        .HasDatabaseName("IX_AccountProfiles_ProfileName_Covering")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_AccountProfileEntity_UniqueId");

                    b.ToTable("AccountProfiles", (string)null);
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.AccountSecureKeyAuthEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<Guid>("AccountId")
                        .HasColumnType("uuid")
                        .HasColumnName("account_id");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<int>("CredentialsVersion")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer")
                        .HasDefaultValue(1)
                        .HasColumnName("credentials_version");

                    b.Property<DateTimeOffset?>("ExpiresAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("expires_at");

                    b.Property<int>("FailedAttempts")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer")
                        .HasDefaultValue(0)
                        .HasColumnName("failed_attempts");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<bool>("IsEnabled")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(true)
                        .HasColumnName("is_enabled");

                    b.Property<bool>("IsPrimary")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_primary");

                    b.Property<DateTimeOffset?>("LastUsedAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("last_used_at");

                    b.Property<DateTimeOffset?>("LockedUntil")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("locked_until");

                    b.Property<byte[]>("MaskingKey")
                        .IsRequired()
                        .HasMaxLength(32)
                        .HasColumnType("bytea")
                        .HasColumnName("masking_key");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<byte[]>("SecureKey")
                        .IsRequired()
                        .HasMaxLength(240)
                        .HasColumnType("bytea")
                        .HasColumnName("secure_key");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_account_secure_key_auth");

                    b.HasIndex("AccountId")
                        .HasDatabaseName("IX_AccountSecureKeyAuth_Account_Enabled")
                        .HasFilter("is_deleted = false AND is_enabled = true");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_AccountSecureKeyAuthEntity_UniqueId");

                    b.HasIndex("AccountId", "IsPrimary")
                        .IsUnique()
                        .HasDatabaseName("UX_AccountSecureKeyAuth_Account_Primary")
                        .HasFilter("is_deleted = false AND is_primary = true");

                    b.ToTable("AccountSecureKeyAuth", (string)null);
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.DeviceContextEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<Guid?>("ActiveAccountId")
                        .HasColumnType("uuid")
                        .HasColumnName("active_account_id");

                    b.Property<DateTimeOffset>("ContextEstablishedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("context_established_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<DateTimeOffset>("ContextExpiresAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("context_expires_at");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<long?>("DeviceEntityId")
                        .HasColumnType("bigint")
                        .HasColumnName("device_entity_id");

                    b.Property<Guid>("DeviceId")
                        .HasColumnType("uuid")
                        .HasColumnName("device_id");

                    b.Property<bool>("IsActive")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(true)
                        .HasColumnName("is_active");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<DateTimeOffset?>("LastActivityAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("last_activity_at");

                    b.Property<Guid>("MembershipId")
                        .HasColumnType("uuid")
                        .HasColumnName("membership_id");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_device_contexts");

                    b.HasIndex("ActiveAccountId")
                        .HasDatabaseName("ix_device_contexts_active_account_id");

                    b.HasIndex("ContextExpiresAt")
                        .HasDatabaseName("IX_DeviceContexts_ExpiresAt")
                        .HasFilter("is_deleted = false AND is_active = true");

                    b.HasIndex("DeviceEntityId")
                        .HasDatabaseName("ix_device_contexts_device_entity_id");

                    b.HasIndex("DeviceId")
                        .HasDatabaseName("IX_DeviceContexts_DeviceId_Active")
                        .HasFilter("is_deleted = false AND is_active = true");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_DeviceContextEntity_UniqueId");

                    b.HasIndex("ContextExpiresAt", "IsActive")
                        .HasDatabaseName("IX_DeviceContexts_ExpiresAt_Cleanup")
                        .HasFilter("is_deleted = false AND is_active = true");

                    b.HasIndex("MembershipId", "DeviceId")
                        .HasDatabaseName("IX_DeviceContexts_Active_Covering")
                        .HasFilter("is_deleted = false AND is_active = true");

                    b.HasIndex("MembershipId", "IsActive")
                        .HasDatabaseName("IX_DeviceContexts_Membership_IsActive")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("MembershipId", "LastActivityAt")
                        .IsDescending(false, true)
                        .HasDatabaseName("IX_DeviceContexts_MembershipActivity")
                        .HasFilter("is_deleted = false AND is_active = true");

                    b.HasIndex("MembershipId", "DeviceId", "IsActive")
                        .IsUnique()
                        .HasDatabaseName("UX_DeviceContexts_Membership_Device_Active")
                        .HasFilter("is_deleted = false AND is_active = true");

                    b.ToTable("DeviceContexts", null, t =>
                        {
                            t.HasCheckConstraint("CHK_DeviceContexts_Activity_Valid", "last_activity_at IS NULL OR last_activity_at >= context_established_at");

                            t.HasCheckConstraint("CHK_DeviceContexts_Expiry_Future", "context_expires_at > context_established_at");
                        });
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.DeviceEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<Guid>("AppInstanceId")
                        .HasColumnType("uuid")
                        .HasColumnName("app_instance_id");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<Guid>("DeviceId")
                        .HasColumnType("uuid")
                        .HasColumnName("device_id");

                    b.Property<int>("DeviceType")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer")
                        .HasDefaultValue(1)
                        .HasColumnName("device_type");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_devices");

                    b.HasAlternateKey("DeviceId")
                        .HasName("ak_devices_device_id");

                    b.HasIndex("AppInstanceId")
                        .IsUnique()
                        .HasDatabaseName("IX_Devices_AppInstanceId")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("DeviceId")
                        .IsUnique()
                        .HasDatabaseName("IX_Devices_DeviceId")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("DeviceType")
                        .HasDatabaseName("IX_Devices_DeviceType")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_DeviceEntity_UniqueId");

                    b.ToTable("Devices", (string)null);
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.FailedOtpAttemptEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<DateTimeOffset>("AttemptedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("attempted_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<string>("AttemptedValue")
                        .IsRequired()
                        .HasMaxLength(10)
                        .HasColumnType("character varying(10)")
                        .HasColumnName("attempted_value");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<string>("FailureReason")
                        .IsRequired()
                        .HasMaxLength(50)
                        .HasColumnType("character varying(50)")
                        .HasColumnName("failure_reason");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<long>("OtpRecordId")
                        .HasColumnType("bigint")
                        .HasColumnName("otp_record_id");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_failed_otp_attempts");

                    b.HasIndex("AttemptedAt")
                        .IsDescending()
                        .HasDatabaseName("IX_FailedOtpAttempts_AttemptedAt")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("OtpRecordId")
                        .HasDatabaseName("IX_FailedOtpAttempts_OtpRecordId");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_FailedOtpAttemptEntity_UniqueId");

                    b.ToTable("FailedOtpAttempts", (string)null);
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.LoginAttemptEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<Guid?>("AccountId")
                        .HasColumnType("uuid")
                        .HasColumnName("account_id");

                    b.Property<DateTimeOffset>("AttemptedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("attempted_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<DateTimeOffset?>("CompletedAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("completed_at");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<Guid?>("DeviceId")
                        .HasColumnType("uuid")
                        .HasColumnName("device_id");

                    b.Property<string>("ErrorMessage")
                        .HasMaxLength(500)
                        .HasColumnType("character varying(500)")
                        .HasColumnName("error_message");

                    b.Property<string>("IpAddress")
                        .HasMaxLength(45)
                        .HasColumnType("character varying(45)")
                        .HasColumnName("ip_address");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<bool>("IsSuccess")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_success");

                    b.Property<DateTimeOffset?>("LockedUntil")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("locked_until");

                    b.Property<Guid?>("MembershipUniqueId")
                        .HasColumnType("uuid")
                        .HasColumnName("membership_unique_id");

                    b.Property<string>("MobileNumber")
                        .HasMaxLength(18)
                        .HasColumnType("character varying(18)")
                        .HasColumnName("mobile_number");

                    b.Property<string>("Outcome")
                        .HasMaxLength(200)
                        .HasColumnType("character varying(200)")
                        .HasColumnName("outcome");

                    b.Property<string>("Platform")
                        .HasMaxLength(50)
                        .HasColumnType("character varying(50)")
                        .HasColumnName("platform");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_login_attempts");

                    b.HasIndex("AccountId")
                        .HasDatabaseName("ix_login_attempts_account_id");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_LoginAttemptEntity_UniqueId");

                    b.HasIndex("DeviceId", "AttemptedAt")
                        .IsDescending(false, true)
                        .HasDatabaseName("ix_login_attempts_device_id_attempted_at")
                        .HasFilter("is_deleted = false AND device_id IS NOT NULL");

                    b.HasIndex("MembershipUniqueId", "Outcome", "AttemptedAt")
                        .HasDatabaseName("IX_LoginAttempts_MembershipCreation")
                        .HasFilter("is_deleted = false AND is_success = false AND outcome = 'membership_creation'");

                    b.HasIndex("MobileNumber", "AttemptedAt", "IsSuccess")
                        .HasDatabaseName("IX_LoginAttempts_CountFailed")
                        .HasFilter("is_deleted = false AND is_success = false AND locked_until IS NULL");

                    b.HasIndex("MobileNumber", "LockedUntil", "AttemptedAt")
                        .IsDescending(false, false, true)
                        .HasDatabaseName("ix_login_attempts_mobile_number_locked_until_attempted_at")
                        .HasFilter("is_deleted = false AND locked_until IS NOT NULL");

                    b.ToTable("LoginAttempts", null, t =>
                        {
                            t.HasCheckConstraint("CHK_LoginAttempts_LockedUntil_Future", "locked_until IS NULL OR locked_until > attempted_at");

                            t.HasCheckConstraint("CHK_LoginAttempts_Success_CompletedAt", "(is_success = false) OR (completed_at IS NOT NULL)");
                        });
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.LogoutAuditEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<Guid?>("AccountId")
                        .HasColumnType("uuid")
                        .HasColumnName("account_id");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<Guid?>("DeviceId")
                        .HasColumnType("uuid")
                        .HasColumnName("device_id");

                    b.Property<string>("IpAddress")
                        .HasMaxLength(45)
                        .HasColumnType("character varying(45)")
                        .HasColumnName("ip_address");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<DateTimeOffset>("LoggedOutAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("logged_out_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<Guid>("MembershipUniqueId")
                        .HasColumnType("uuid")
                        .HasColumnName("membership_unique_id");

                    b.Property<string>("Platform")
                        .HasMaxLength(50)
                        .HasColumnType("character varying(50)")
                        .HasColumnName("platform");

                    b.Property<string>("Reason")
                        .IsRequired()
                        .HasMaxLength(50)
                        .HasColumnType("character varying(50)")
                        .HasColumnName("reason");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_logout_audits");

                    b.HasIndex("AccountId")
                        .HasDatabaseName("ix_logout_audits_account_id");

                    b.HasIndex("DeviceId")
                        .HasDatabaseName("IX_LogoutAudits_DeviceId")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("LoggedOutAt")
                        .IsDescending()
                        .HasDatabaseName("IX_LogoutAudits_LoggedOutAt")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_LogoutAuditEntity_UniqueId");

                    b.HasIndex("MembershipUniqueId", "LoggedOutAt")
                        .IsDescending(false, true)
                        .HasDatabaseName("IX_LogoutAudits_Membership_LoggedOutAt")
                        .HasFilter("is_deleted = false");

                    b.ToTable("LogoutAudits", (string)null);
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.MasterKeyShareEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<int>("CredentialsVersion")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer")
                        .HasDefaultValue(1)
                        .HasColumnName("credentials_version");

                    b.Property<byte[]>("EncryptedShare")
                        .IsRequired()
                        .HasColumnType("bytea")
                        .HasColumnName("encrypted_share");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<Guid>("MembershipUniqueId")
                        .HasColumnType("uuid")
                        .HasColumnName("membership_unique_id");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<int>("ShareIndex")
                        .HasColumnType("integer")
                        .HasColumnName("share_index");

                    b.Property<string>("ShareMetadata")
                        .IsRequired()
                        .HasColumnType("varchar(500)")
                        .HasColumnName("share_metadata");

                    b.Property<string>("StorageLocation")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("character varying(100)")
                        .HasColumnName("storage_location");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_master_key_shares");

                    b.HasIndex("ShareIndex")
                        .HasDatabaseName("IX_MasterKeyShares_ShareIndex");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_MasterKeyShareEntity_UniqueId");

                    b.HasIndex("MembershipUniqueId", "ShareIndex")
                        .IsUnique()
                        .HasDatabaseName("UQ_MasterKeyShares_MembershipShare");

                    b.ToTable("MasterKeyShares", (string)null);
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.MembershipEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<Guid>("AppDeviceId")
                        .HasColumnType("uuid")
                        .HasColumnName("app_device_id");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<string>("CreationStatus")
                        .HasMaxLength(20)
                        .HasColumnType("character varying(20)")
                        .HasColumnName("creation_status");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<Guid>("MobileNumberId")
                        .HasColumnType("uuid")
                        .HasColumnName("mobile_number_id");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<string>("Status")
                        .IsRequired()
                        .ValueGeneratedOnAdd()
                        .HasMaxLength(20)
                        .HasColumnType("character varying(20)")
                        .HasDefaultValue("inactive")
                        .HasColumnName("status");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<Guid?>("VerificationFlowId")
                        .HasColumnType("uuid")
                        .HasColumnName("verification_flow_id");

                    b.HasKey("Id")
                        .HasName("pk_memberships");

                    b.HasAlternateKey("UniqueId")
                        .HasName("ak_memberships_unique_id");

                    b.HasIndex("AppDeviceId")
                        .HasDatabaseName("IX_Memberships_AppDeviceId");

                    b.HasIndex("MobileNumberId")
                        .IsUnique()
                        .HasDatabaseName("UQ_Memberships_ActiveMembership")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("Status")
                        .HasDatabaseName("IX_Memberships_Status")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_Memberships_UniqueId");

                    b.HasIndex("VerificationFlowId")
                        .HasDatabaseName("ix_memberships_verification_flow_id");

                    b.ToTable("Memberships", null, t =>
                        {
                            t.HasCheckConstraint("CHK_Memberships_CreationStatus", "creation_status IN ('otp_verified', 'secure_key_set', 'passphrase_set')");

                            t.HasCheckConstraint("CHK_Memberships_Status", "status IN ('active', 'inactive')");
                        });
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.MembershipRelationEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<long>("InitiatorAccountId")
                        .HasColumnType("bigint")
                        .HasColumnName("initiator_account_id");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<string>("Message")
                        .HasMaxLength(512)
                        .IsUnicode(true)
                        .HasColumnType("character varying(512)")
                        .HasColumnName("message");

                    b.Property<string>("MetaJson")
                        .HasColumnType("text")
                        .HasColumnName("meta_json");

                    b.Property<DateTimeOffset?>("MutedUntil")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("muted_until");

                    b.Property<long>("RecipientAccountId")
                        .HasColumnType("bigint")
                        .HasColumnName("recipient_account_id");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<string>("Status")
                        .HasColumnType("text")
                        .HasColumnName("status");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_membership_relations");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_MembershipRelationEntity_UniqueId");

                    b.HasIndex("InitiatorAccountId", "RecipientAccountId")
                        .HasDatabaseName("IX_MembershipRelations_InitiatorRecipient")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("RecipientAccountId", "InitiatorAccountId")
                        .HasDatabaseName("IX_MembershipRelations_RecipientInitiator")
                        .HasFilter("is_deleted = false");

                    b.ToTable("MembershipRelations", (string)null);
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.MobileNumberEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<string>("Number")
                        .IsRequired()
                        .HasMaxLength(18)
                        .HasColumnType("character varying(18)")
                        .HasColumnName("number");

                    b.Property<string>("Region")
                        .HasMaxLength(2)
                        .HasColumnType("character varying(2)")
                        .HasColumnName("region");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_mobile_numbers");

                    b.HasAlternateKey("UniqueId")
                        .HasName("ak_mobile_numbers_unique_id");

                    b.HasIndex("CreatedAt")
                        .IsDescending()
                        .HasDatabaseName("IX_MobileNumbers_CreatedAt")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("Number")
                        .IsUnique()
                        .HasDatabaseName("UQ_MobileNumbers_Number");

                    b.HasIndex("Region")
                        .HasDatabaseName("IX_MobileNumbers_Region")
                        .HasFilter("is_deleted = false AND Region IS NOT NULL");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_MobileNumberEntity_UniqueId");

                    b.HasIndex("Number", "Region")
                        .HasDatabaseName("IX_MobileNumbers_MobileNumber_Region")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("Number", "Region", "IsDeleted")
                        .IsUnique()
                        .HasDatabaseName("UQ_MobileNumbers_ActiveNumberRegion");

                    b.ToTable("MobileNumbers", (string)null);
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.OtpCodeEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<short>("AttemptCount")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("smallint")
                        .HasDefaultValue((short)0)
                        .HasColumnName("attempt_count");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<DateTimeOffset>("ExpiresAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("expires_at");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<string>("OtpSalt")
                        .IsRequired()
                        .HasMaxLength(32)
                        .HasColumnType("character varying(32)")
                        .HasColumnName("otp_salt");

                    b.Property<string>("OtpValue")
                        .IsRequired()
                        .HasMaxLength(64)
                        .HasColumnType("character varying(64)")
                        .HasColumnName("otp_value");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<string>("Status")
                        .IsRequired()
                        .ValueGeneratedOnAdd()
                        .HasMaxLength(20)
                        .HasColumnType("character varying(20)")
                        .HasDefaultValue("active")
                        .HasColumnName("status");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<long>("VerificationFlowId")
                        .HasColumnType("bigint")
                        .HasColumnName("verification_flow_id");

                    b.Property<DateTimeOffset?>("VerifiedAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("verified_at");

                    b.HasKey("Id")
                        .HasName("pk_otp_codes");

                    b.HasIndex("ExpiresAt")
                        .HasDatabaseName("IX_OtpCodes_ExpiresAt")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("Status")
                        .HasDatabaseName("IX_OtpCodes_Status")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_OtpCodeEntity_UniqueId");

                    b.HasIndex("VerificationFlowId")
                        .HasDatabaseName("IX_OtpCodes_VerificationFlowId");

                    b.ToTable("OtpCodes", null, t =>
                        {
                            t.HasCheckConstraint("CHK_OtpCodes_Status", "status IN ('active', 'used', 'expired', 'invalid')");
                        });
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.VerificationFlowEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<Guid>("AppDeviceId")
                        .HasColumnType("uuid")
                        .HasColumnName("app_device_id");

                    b.Property<long?>("ConnectionId")
                        .HasColumnType("bigint")
                        .HasColumnName("connection_id");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<DateTimeOffset>("ExpiresAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("expires_at");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<DateTimeOffset?>("LastOtpSentAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("last_otp_sent_at");

                    b.Property<Guid>("MobileNumberId")
                        .HasColumnType("uuid")
                        .HasColumnName("mobile_number_id");

                    b.Property<short>("OtpCount")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("smallint")
                        .HasDefaultValue((short)0)
                        .HasColumnName("otp_count");

                    b.Property<string>("Purpose")
                        .IsRequired()
                        .ValueGeneratedOnAdd()
                        .HasMaxLength(30)
                        .HasColumnType("character varying(30)")
                        .HasDefaultValue("unspecified")
                        .HasColumnName("purpose");

                    b.Property<DateTimeOffset?>("ResendAvailableAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("resend_available_at");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<string>("Status")
                        .IsRequired()
                        .ValueGeneratedOnAdd()
                        .HasMaxLength(20)
                        .HasColumnType("character varying(20)")
                        .HasDefaultValue("pending")
                        .HasColumnName("status");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.HasKey("Id")
                        .HasName("pk_verification_flows");

                    b.HasAlternateKey("UniqueId")
                        .HasName("ak_verification_flows_unique_id");

                    b.HasIndex("AppDeviceId")
                        .HasDatabaseName("IX_VerificationFlows_AppDeviceId");

                    b.HasIndex("ExpiresAt")
                        .HasDatabaseName("IX_VerificationFlows_ExpiresAt")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("MobileNumberId")
                        .HasDatabaseName("IX_VerificationFlows_MobileNumberId");

                    b.HasIndex("Status")
                        .HasDatabaseName("IX_VerificationFlows_Status")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_VerificationFlowEntity_UniqueId");

                    b.HasIndex("UniqueId", "LastOtpSentAt", "OtpCount", "ExpiresAt")
                        .HasDatabaseName("IX_VerificationFlows_CooldownCheck")
                        .HasFilter("is_deleted = false AND status = 'pending'");

                    b.ToTable("VerificationFlows", null, t =>
                        {
                            t.HasCheckConstraint("CHK_VerificationFlows_Purpose", "purpose IN ('unspecified', 'registration', 'login', 'password_recovery', 'secure_key_recovery', 'update_phone')");

                            t.HasCheckConstraint("CHK_VerificationFlows_Status", "status IN ('pending', 'verified', 'expired', 'failed')");
                        });
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.VerificationLogEntity", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint")
                        .HasColumnName("id");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<long>("Id"));

                    b.Property<Guid?>("AccountId")
                        .HasColumnType("uuid")
                        .HasColumnName("account_id");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<Guid>("DeviceId")
                        .HasColumnType("uuid")
                        .HasColumnName("device_id");

                    b.Property<DateTimeOffset?>("ExpiresAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("expires_at");

                    b.Property<bool>("IsDeleted")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("boolean")
                        .HasDefaultValue(false)
                        .HasColumnName("is_deleted");

                    b.Property<Guid>("MembershipId")
                        .HasColumnType("uuid")
                        .HasColumnName("membership_id");

                    b.Property<Guid>("MobileNumberId")
                        .HasColumnType("uuid")
                        .HasColumnName("mobile_number_id");

                    b.Property<short>("OtpCount")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("smallint")
                        .HasDefaultValue((short)0)
                        .HasColumnName("otp_count");

                    b.Property<string>("Purpose")
                        .IsRequired()
                        .HasMaxLength(50)
                        .HasColumnType("character varying(50)")
                        .HasColumnName("purpose");

                    b.Property<byte[]>("RowVersion")
                        .IsConcurrencyToken()
                        .IsRequired()
                        .ValueGeneratedOnAddOrUpdate()
                        .HasColumnType("bytea")
                        .HasDefaultValue(new byte[] { 0 })
                        .HasColumnName("row_version");

                    b.Property<string>("Status")
                        .IsRequired()
                        .HasMaxLength(20)
                        .HasColumnType("character varying(20)")
                        .HasColumnName("status");

                    b.Property<Guid>("UniqueId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid")
                        .HasColumnName("unique_id")
                        .HasDefaultValueSql("gen_random_uuid()");

                    b.Property<DateTimeOffset>("UpdatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("updated_at")
                        .HasDefaultValueSql("CURRENT_TIMESTAMP");

                    b.Property<DateTimeOffset>("VerifiedAt")
                        .HasColumnType("timestamp with time zone")
                        .HasColumnName("verified_at");

                    b.HasKey("Id")
                        .HasName("pk_verification_logs");

                    b.HasIndex("AccountId")
                        .HasDatabaseName("ix_verification_logs_account_id");

                    b.HasIndex("DeviceId")
                        .HasDatabaseName("IX_VerificationLogs_DeviceId")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("MembershipId")
                        .HasDatabaseName("IX_VerificationLogs_Membership")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("MobileNumberId")
                        .HasDatabaseName("ix_verification_logs_mobile_number_id");

                    b.HasIndex("UniqueId")
                        .IsUnique()
                        .HasDatabaseName("UQ_VerificationLogEntity_UniqueId");

                    b.HasIndex("VerifiedAt")
                        .IsDescending()
                        .HasDatabaseName("IX_VerificationLogs_VerifiedAt")
                        .HasFilter("is_deleted = false");

                    b.HasIndex("MembershipId", "Purpose")
                        .HasDatabaseName("IX_VerificationLogs_Membership_Purpose")
                        .HasFilter("is_deleted = false");

                    b.ToTable("VerificationLogs", (string)null);
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.AccountEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.MembershipEntity", "Membership")
                        .WithMany("Accounts")
                        .HasForeignKey("MembershipId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired()
                        .HasConstraintName("FK_Accounts_Memberships");

                    b.Navigation("Membership");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.AccountPinAuthEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.AccountEntity", "Account")
                        .WithMany("PinAuths")
                        .HasForeignKey("AccountId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired()
                        .HasConstraintName("FK_AccountPinAuth_Accounts");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.DeviceEntity", "Device")
                        .WithMany()
                        .HasForeignKey("DeviceId")
                        .HasPrincipalKey("DeviceId")
                        .OnDelete(DeleteBehavior.NoAction)
                        .HasConstraintName("FK_AccountPinAuth_Devices");

                    b.Navigation("Account");

                    b.Navigation("Device");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.AccountProfileEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.AccountEntity", "Account")
                        .WithOne("Profile")
                        .HasForeignKey("Ecliptix.Domain.Schema.Entities.AccountProfileEntity", "AccountId")
                        .HasPrincipalKey("Ecliptix.Domain.Schema.Entities.AccountEntity", "UniqueId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired()
                        .HasConstraintName("FK_AccountProfiles_Accounts");

                    b.Navigation("Account");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.AccountSecureKeyAuthEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.AccountEntity", "Account")
                        .WithMany("SecureKeyAuths")
                        .HasForeignKey("AccountId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired()
                        .HasConstraintName("FK_AccountSecureKeyAuth_Accounts");

                    b.Navigation("Account");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.DeviceContextEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.AccountEntity", "ActiveAccount")
                        .WithMany()
                        .HasForeignKey("ActiveAccountId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.NoAction)
                        .HasConstraintName("FK_DeviceContexts_Accounts");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.DeviceEntity", null)
                        .WithMany("DeviceContexts")
                        .HasForeignKey("DeviceEntityId")
                        .HasConstraintName("fk_device_contexts_devices_device_entity_id");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.DeviceEntity", "Device")
                        .WithMany()
                        .HasForeignKey("DeviceId")
                        .HasPrincipalKey("DeviceId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired()
                        .HasConstraintName("FK_DeviceContexts_Devices");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.MembershipEntity", "Membership")
                        .WithMany("DeviceContexts")
                        .HasForeignKey("MembershipId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired()
                        .HasConstraintName("FK_DeviceContexts_Memberships");

                    b.Navigation("ActiveAccount");

                    b.Navigation("Device");

                    b.Navigation("Membership");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.FailedOtpAttemptEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.OtpCodeEntity", "OtpRecord")
                        .WithMany("FailedAttempts")
                        .HasForeignKey("OtpRecordId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired()
                        .HasConstraintName("FK_FailedOtpAttempts_OtpCodes");

                    b.Navigation("OtpRecord");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.LoginAttemptEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.AccountEntity", "Account")
                        .WithMany("LoginAttempts")
                        .HasForeignKey("AccountId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.NoAction)
                        .HasConstraintName("FK_LoginAttempts_Accounts");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.DeviceEntity", "Device")
                        .WithMany()
                        .HasForeignKey("DeviceId")
                        .HasPrincipalKey("DeviceId")
                        .OnDelete(DeleteBehavior.NoAction)
                        .HasConstraintName("FK_LoginAttempts_Devices");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.MembershipEntity", "Membership")
                        .WithMany("LoginAttempts")
                        .HasForeignKey("MembershipUniqueId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .HasConstraintName("FK_LoginAttempts_Memberships");

                    b.Navigation("Account");

                    b.Navigation("Device");

                    b.Navigation("Membership");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.LogoutAuditEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.AccountEntity", "Account")
                        .WithMany("LogoutAudits")
                        .HasForeignKey("AccountId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.SetNull)
                        .HasConstraintName("FK_LogoutAudits_Accounts");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.MembershipEntity", "Membership")
                        .WithMany()
                        .HasForeignKey("MembershipUniqueId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired()
                        .HasConstraintName("FK_LogoutAudits_Memberships");

                    b.Navigation("Account");

                    b.Navigation("Membership");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.MasterKeyShareEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.MembershipEntity", "Membership")
                        .WithMany("MasterKeyShares")
                        .HasForeignKey("MembershipUniqueId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.NoAction)
                        .IsRequired()
                        .HasConstraintName("FK_MasterKeyShares_Memberships");

                    b.Navigation("Membership");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.MembershipEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.DeviceEntity", "AppDevice")
                        .WithMany("Memberships")
                        .HasForeignKey("AppDeviceId")
                        .HasPrincipalKey("DeviceId")
                        .OnDelete(DeleteBehavior.NoAction)
                        .IsRequired()
                        .HasConstraintName("FK_Memberships_Devices");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.MobileNumberEntity", "MobileNumber")
                        .WithMany("Memberships")
                        .HasForeignKey("MobileNumberId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.NoAction)
                        .IsRequired()
                        .HasConstraintName("FK_Memberships_MobileNumbers");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.VerificationFlowEntity", "VerificationFlow")
                        .WithMany("Memberships")
                        .HasForeignKey("VerificationFlowId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.NoAction)
                        .HasConstraintName("FK_Memberships_VerificationFlows");

                    b.Navigation("AppDevice");

                    b.Navigation("MobileNumber");

                    b.Navigation("VerificationFlow");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.MembershipRelationEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.AccountEntity", "InitiatorAccount")
                        .WithMany()
                        .HasForeignKey("InitiatorAccountId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired()
                        .HasConstraintName("fk_membership_relations_accounts_initiator_account_id");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.AccountEntity", "RecipientAccount")
                        .WithMany()
                        .HasForeignKey("RecipientAccountId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired()
                        .HasConstraintName("fk_membership_relations_accounts_recipient_account_id");

                    b.Navigation("InitiatorAccount");

                    b.Navigation("RecipientAccount");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.OtpCodeEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.VerificationFlowEntity", "VerificationFlow")
                        .WithMany("OtpCodes")
                        .HasForeignKey("VerificationFlowId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired()
                        .HasConstraintName("FK_OtpCodes_VerificationFlows");

                    b.Navigation("VerificationFlow");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.VerificationFlowEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.DeviceEntity", "AppDevice")
                        .WithMany("VerificationFlows")
                        .HasForeignKey("AppDeviceId")
                        .HasPrincipalKey("DeviceId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired()
                        .HasConstraintName("FK_VerificationFlows_Devices");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.MobileNumberEntity", "MobileNumber")
                        .WithMany("VerificationFlows")
                        .HasForeignKey("MobileNumberId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired()
                        .HasConstraintName("FK_VerificationFlows_MobileNumbers");

                    b.Navigation("AppDevice");

                    b.Navigation("MobileNumber");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.VerificationLogEntity", b =>
                {
                    b.HasOne("Ecliptix.Domain.Schema.Entities.AccountEntity", "Account")
                        .WithMany("VerificationLogs")
                        .HasForeignKey("AccountId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.NoAction)
                        .HasConstraintName("FK_VerificationLogs_Accounts");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.DeviceEntity", "Device")
                        .WithMany()
                        .HasForeignKey("DeviceId")
                        .HasPrincipalKey("DeviceId")
                        .OnDelete(DeleteBehavior.NoAction)
                        .IsRequired()
                        .HasConstraintName("FK_VerificationLogs_Devices");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.MembershipEntity", "Membership")
                        .WithMany("VerificationLogs")
                        .HasForeignKey("MembershipId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired()
                        .HasConstraintName("FK_VerificationLogs_Memberships");

                    b.HasOne("Ecliptix.Domain.Schema.Entities.MobileNumberEntity", "MobileNumber")
                        .WithMany()
                        .HasForeignKey("MobileNumberId")
                        .HasPrincipalKey("UniqueId")
                        .OnDelete(DeleteBehavior.NoAction)
                        .IsRequired()
                        .HasConstraintName("FK_VerificationLogs_MobileNumbers");

                    b.Navigation("Account");

                    b.Navigation("Device");

                    b.Navigation("Membership");

                    b.Navigation("MobileNumber");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.AccountEntity", b =>
                {
                    b.Navigation("LoginAttempts");

                    b.Navigation("LogoutAudits");

                    b.Navigation("PinAuths");

                    b.Navigation("Profile")
                        .IsRequired();

                    b.Navigation("SecureKeyAuths");

                    b.Navigation("VerificationLogs");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.DeviceEntity", b =>
                {
                    b.Navigation("DeviceContexts");

                    b.Navigation("Memberships");

                    b.Navigation("VerificationFlows");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.MembershipEntity", b =>
                {
                    b.Navigation("Accounts");

                    b.Navigation("DeviceContexts");

                    b.Navigation("LoginAttempts");

                    b.Navigation("MasterKeyShares");

                    b.Navigation("VerificationLogs");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.MobileNumberEntity", b =>
                {
                    b.Navigation("Memberships");

                    b.Navigation("VerificationFlows");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.OtpCodeEntity", b =>
                {
                    b.Navigation("FailedAttempts");
                });

            modelBuilder.Entity("Ecliptix.Domain.Schema.Entities.VerificationFlowEntity", b =>
                {
                    b.Navigation("Memberships");

                    b.Navigation("OtpCodes");
                });
#pragma warning restore 612, 618
        }
    }
}
