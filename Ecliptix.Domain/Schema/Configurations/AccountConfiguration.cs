using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Schema.Configurations;

public class AccountConfiguration : EntityBaseMap<AccountEntity>
{
    public override void Map(EntityTypeBuilder<AccountEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("Accounts");

        builder.Property(e => e.MembershipId)
            .IsRequired();

        builder.Property(e => e.AccountType)
            .IsRequired();

        builder.Property(e => e.AccountName)
            .IsRequired()
            .HasMaxLength(200);

        builder.Property(e => e.Status)
            .IsRequired();

        builder.Property(e => e.IsDefaultAccount)
            .HasDefaultValue(false);

        builder.Property(e => e.PreferredLanguage)
            .HasMaxLength(10);

        builder.Property(e => e.TimeZoneId)
            .HasMaxLength(100);

        builder.Property(e => e.CountryCode)
            .HasMaxLength(2);

        builder.Property(e => e.DataResidencyRegion)
            .HasMaxLength(50);

        builder.Property(e => e.LastAccessedAt)
            .HasColumnType("DATETIMEOFFSET");

        builder.HasIndex(e => new { e.MembershipId, e.AccountType })
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_Accounts_Membership_Type");

        builder.HasIndex(e => new { e.MembershipId, e.IsDefaultAccount })
            .IsUnique()
            .HasFilter("IsDeleted = 0 AND IsDefaultAccount = 1")
            .HasDatabaseName("UX_Accounts_Membership_Default");

        builder.HasIndex(e => e.Status)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_Accounts_Status");

        builder.ToTable(t => t.HasCheckConstraint("CHK_Accounts_Default_Active",
            "(IsDefaultAccount = 0) OR (Status != 2)"));

        Microsoft.EntityFrameworkCore.SqlServerIndexBuilderExtensions.IncludeProperties(
            builder.HasIndex(e => e.MembershipId)
                .HasFilter("IsDeleted = 0 AND Status = 1"),
            e => new { e.UniqueId, e.AccountType, e.AccountName, e.IsDefaultAccount })
            .HasDatabaseName("IX_Accounts_Membership_Active_Covering");

        builder.HasOne(e => e.Membership)
            .WithMany(m => m.Accounts)
            .HasForeignKey(e => e.MembershipId)
            .HasPrincipalKey(m => m.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired()
            .HasConstraintName("FK_Accounts_Memberships");
    }
}
