using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.IdentityAccess.Domain.Schema.Configurations;

public class AccountPinAuthConfiguration : EntityBaseMap<AccountPinAuthEntity>
{
    public override void Map(EntityTypeBuilder<AccountPinAuthEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("AccountPinAuth");

        builder.Property(e => e.AccountId)
            .IsRequired();

        builder.Property(e => e.DeviceId)
            .IsRequired(false);

        builder.Property(e => e.SecureKey)
            .IsRequired()
            .HasColumnType("bytea")
            .HasMaxLength(176);

        builder.Property(e => e.MaskingKey)
            .IsRequired()
            .HasColumnType("bytea")
            .HasMaxLength(32);

        builder.Property(e => e.CredentialsVersion)
            .HasDefaultValue(1);

        builder.Property(e => e.IsPrimary)
            .HasDefaultValue(false);

        builder.Property(e => e.IsEnabled)
            .HasDefaultValue(true);

        builder.Property(e => e.IsDeviceSpecific)
            .HasDefaultValue(false);

        builder.Property(e => e.PinLength)
            .HasDefaultValue(6);

        builder.Property(e => e.FailedAttempts)
            .HasDefaultValue(0);

        builder.Property(e => e.LastUsedAt)
            .HasColumnType("timestamp with time zone");

        builder.Property(e => e.LockedUntil)
            .HasColumnType("timestamp with time zone");

        builder.HasIndex(e => new { e.AccountId, e.DeviceId })
            .IsUnique()
            .HasFilter("is_deleted = false AND is_device_specific = true AND device_id IS NOT NULL")
            .HasDatabaseName("UX_AccountPinAuth_Account_Device");

        builder.HasIndex(e => e.AccountId)
            .HasFilter("is_deleted = false AND is_enabled = true")
            .HasDatabaseName("IX_AccountPinAuth_Account_Enabled");

        builder.HasIndex(e => new { e.AccountId, e.DeviceId })
            .HasFilter("is_deleted = false AND is_enabled = true")
            .HasDatabaseName("IX_AccountPinAuth_Covering");

        builder.HasOne(e => e.Account)
            .WithMany(a => a.PinAuths)
            .HasForeignKey(e => e.AccountId)
            .HasPrincipalKey(a => a.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired()
            .HasConstraintName("FK_AccountPinAuth_Accounts");

        builder.HasOne(e => e.Device)
            .WithMany()
            .HasForeignKey(e => e.DeviceId)
            .HasPrincipalKey(d => d.DeviceId)
            .OnDelete(DeleteBehavior.NoAction)
            .IsRequired(false)
            .HasConstraintName("FK_AccountPinAuth_Devices");
    }
}
