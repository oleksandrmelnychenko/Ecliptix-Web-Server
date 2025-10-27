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

        builder.Property(e => e.FailedAttempts)
            .HasDefaultValue(0);

        builder.Property(e => e.LastUsedAt)
            .HasColumnType("DATETIMEOFFSET");

        builder.Property(e => e.ExpiresAt)
            .HasColumnType("DATETIMEOFFSET");

        builder.Property(e => e.LockedUntil)
            .HasColumnType("DATETIMEOFFSET");

        // Indexes
        builder.HasIndex(e => new { e.AccountId, e.IsPrimary })
            .IsUnique()
            .HasFilter("IsDeleted = 0 AND IsPrimary = 1")
            .HasDatabaseName("UX_AccountSecureKeyAuth_Account_Primary");

        builder.HasIndex(e => e.AccountId)
            .HasFilter("IsDeleted = 0 AND IsEnabled = 1")
            .HasDatabaseName("IX_AccountSecureKeyAuth_Account_Enabled");

        Microsoft.EntityFrameworkCore.SqlServerIndexBuilderExtensions.IncludeProperties(
            builder.HasIndex(e => e.AccountId)
                .HasFilter("IsDeleted = 0 AND IsEnabled = 1"),
            e => new { e.UniqueId, e.SecureKey, e.MaskingKey, e.CredentialsVersion, e.IsPrimary })
            .HasDatabaseName("IX_AccountSecureKeyAuth_Covering");

        // Foreign key
        builder.HasOne(e => e.Account)
            .WithMany(a => a.SecureKeyAuths)
            .HasForeignKey(e => e.AccountId)
            .HasPrincipalKey(a => a.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired()
            .HasConstraintName("FK_AccountSecureKeyAuth_Accounts");
    }
}
