using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

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
            .HasColumnType("timestamp with time zone");

        builder.HasIndex(e => new { e.MembershipId, e.AccountType })
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_Accounts_Membership_Type");

        builder.HasIndex(e => new { e.MembershipId, e.IsDefaultAccount })
            .IsUnique()
            .HasFilter("is_deleted = false AND is_default_account = true")
            .HasDatabaseName("UX_Accounts_Membership_Default");

        builder.HasIndex(e => e.Status)
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_Accounts_Status");

        builder.ToTable(t => t.HasCheckConstraint("CHK_Accounts_Default_Active",
            "(is_default_account = false) OR (status != 2)"));

        IndexBuilder<AccountEntity> idx = builder.HasIndex(e => e.MembershipId)
            .HasFilter("is_deleted = false AND status = 1");

        builder.HasOne(e => e.Membership)
            .WithMany(m => m.Accounts)
            .HasForeignKey(e => e.MembershipId)
            .HasPrincipalKey(m => m.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired()
            .HasConstraintName("FK_Accounts_Memberships");
    }
}
