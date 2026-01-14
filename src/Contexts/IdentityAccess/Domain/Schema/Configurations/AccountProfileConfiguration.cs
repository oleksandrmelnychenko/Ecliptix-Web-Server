using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.IdentityAccess.Domain.Schema.Configurations;

public class AccountProfileConfiguration : EntityBaseMap<AccountProfileEntity>
{
    public override void Map(EntityTypeBuilder<AccountProfileEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("account_profiles");

        builder.Property(e => e.AccountId)
            .IsRequired();

        builder.Property(e => e.ProfileName)
            .IsRequired()
            .HasMaxLength(50);

        builder.Property(e => e.DisplayName)
            .IsRequired()
            .HasMaxLength(100);

        builder.HasIndex(e => e.AccountId)
            .IsUnique()
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_AccountProfiles_AccountId_Unique");

        builder.HasIndex(e => e.ProfileName)
            .IsUnique()
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_AccountProfiles_ProfileName_Covering");

        builder.HasOne(e => e.Account)
            .WithOne(a => a.Profile)
            .HasForeignKey<AccountProfileEntity>(e => e.AccountId)
            .HasPrincipalKey<AccountEntity>(a => a.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_AccountProfiles_Accounts");
    }
}
