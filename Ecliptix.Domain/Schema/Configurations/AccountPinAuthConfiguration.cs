using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema.Configurations;

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
            .HasColumnType("VARBINARY(176)");

        builder.Property(e => e.MaskingKey)
            .IsRequired()
            .HasColumnType("VARBINARY(32)");

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
            .HasColumnType("DATETIMEOFFSET");

        builder.Property(e => e.LockedUntil)
            .HasColumnType("DATETIMEOFFSET");

        builder.HasIndex(e => new { e.AccountId, e.DeviceId })
            .IsUnique()
            .HasFilter("IsDeleted = 0 AND IsDeviceSpecific = 1 AND DeviceId IS NOT NULL")
            .HasDatabaseName("UX_AccountPinAuth_Account_Device");

        builder.HasIndex(e => e.AccountId)
            .HasFilter("IsDeleted = 0 AND IsEnabled = 1")
            .HasDatabaseName("IX_AccountPinAuth_Account_Enabled");

        Microsoft.EntityFrameworkCore.SqlServerIndexBuilderExtensions.IncludeProperties(
            builder.HasIndex(e => new { e.AccountId, e.DeviceId })
                .HasFilter("IsDeleted = 0 AND IsEnabled = 1"),
            e => new { e.UniqueId, e.SecureKey, e.MaskingKey, e.CredentialsVersion, e.IsDeviceSpecific })
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
            .HasPrincipalKey(d => d.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .IsRequired(false)
            .HasConstraintName("FK_AccountPinAuth_Devices");
    }
}
