using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema.Configurations;

public class AccountSecureKeyAuthConfiguration : EntityBaseMap<AccountSecureKeyAuthEntity>
{
    public override void Map(EntityTypeBuilder<AccountSecureKeyAuthEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("AccountSecureKeyAuth");

        builder.Property(e => e.AccountId)
            .IsRequired();

        builder.Property(e => e.SecureKey)
            .IsRequired()
            .HasColumnType("bytea")
            .HasMaxLength(240);

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

        builder.Property(e => e.FailedAttempts)
            .HasDefaultValue(0);

        builder.Property(e => e.LastUsedAt)
            .HasColumnType("timestamp with time zone");

        builder.Property(e => e.ExpiresAt)
            .HasColumnType("timestamp with time zone");

        builder.Property(e => e.LockedUntil)
            .HasColumnType("timestamp with time zone");

        builder.HasIndex(e => new { e.AccountId, e.IsPrimary })
            .IsUnique()
            .HasFilter("is_deleted = false AND is_primary = true")
            .HasDatabaseName("UX_AccountSecureKeyAuth_Account_Primary");

        builder.HasIndex(e => e.AccountId)
            .HasFilter("is_deleted = false AND is_enabled = true")
            .HasDatabaseName("IX_AccountSecureKeyAuth_Account_Enabled");

        builder.HasOne(e => e.Account)
            .WithMany(a => a.SecureKeyAuths)
            .HasForeignKey(e => e.AccountId)
            .HasPrincipalKey(a => a.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired()
            .HasConstraintName("FK_AccountSecureKeyAuth_Accounts");
    }
}
