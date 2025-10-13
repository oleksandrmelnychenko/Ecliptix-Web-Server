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
        
        builder.Property(e => e.MobileNumberId)
            .IsRequired();
        
        builder.Property(e => e.SecureKey)
            .HasColumnType("VARBINARY(176)");

        builder.Property(e => e.MaskingKey)
            .HasColumnType("VARBINARY(32)");
        
        builder.Property(e => e.CredentialsVersion)
            .IsRequired();
        
        builder.Property(e => e.Status)
            .IsRequired()
            .HasMaxLength(20)
            .HasDefaultValue("inactive");

        builder.Property(e => e.CreationStatus)
            .HasMaxLength(20);
        
        builder.ToTable(t => t.HasCheckConstraint("CHK_Accounts_Status",
            "Status IN ('active', 'inactive')"));
        
        builder.ToTable(t => t.HasCheckConstraint("CHK_Account_CreationStatus",
            "CreationStatus IN ('otp_verified', 'secure_key_set', 'passphrase_set')"));
        
        builder.HasIndex(e => new { e.MobileNumberId, e.IsDeleted })
            .IsUnique()
            .HasDatabaseName("UQ_Accounts_ActiveAccount");
        
        builder.HasIndex(e => e.MembershipId)
            .HasDatabaseName("IX_Accounts_MembershipId");
        
        builder.HasIndex(e => e.Status)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_Memberships_Status");

        builder.HasOne(e => e.Membership)
            .WithMany(m => m.Accounts)
            .HasForeignKey(e => e.MembershipId)
            .HasPrincipalKey(p => p.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .HasConstraintName("FK_Accounts_Memberships");

        builder.HasOne(e => e.MobileNumber)
            .WithMany(mn => mn.Accounts)
            .HasForeignKey(e => e.MobileNumberId)
            .HasPrincipalKey(p => p.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .HasConstraintName("FK_Accounts_MobileNumbers");
        
        builder.HasMany(e => e.MobileDevices)
            .WithOne(md => md.Account)
            .HasForeignKey(md => md.AccountId)
            .OnDelete(DeleteBehavior.NoAction)
            .HasConstraintName("FK_MobileDevices_Accounts");

        builder.HasMany(e => e.LoginAttempts)
            .WithOne(la => la.Account)
            .HasForeignKey(la => la.AccountId)
            .OnDelete(DeleteBehavior.NoAction)
            .HasConstraintName("FK_LoginAttempts_Accounts");
    }
}