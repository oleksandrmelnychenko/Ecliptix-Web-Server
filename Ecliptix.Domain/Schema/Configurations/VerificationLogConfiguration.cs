using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Domain.Schema.ValueConverters;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema.Configurations;

public class VerificationLogConfiguration : EntityBaseMap<VerificationLogEntity>
{
    public override void Map(EntityTypeBuilder<VerificationLogEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("VerificationLogs");

        builder.Property(e => e.MembershipId)
            .IsRequired();

        builder.Property(e => e.MobileNumberId)
            .IsRequired();

        builder.Property(e => e.DeviceId)
            .IsRequired();

        builder.Property(e => e.AccountId)
            .IsRequired(false);

        builder.Property(e => e.Purpose)
            .IsRequired()
            .HasMaxLength(50)
            .HasConversion(new EnumToSnakeCaseConverter<VerificationPurpose>());

        builder.Property(e => e.Status)
            .IsRequired()
            .HasMaxLength(20)
            .HasConversion(new EnumToSnakeCaseConverter<VerificationFlowStatus>());

        builder.Property(e => e.OtpCount)
            .HasDefaultValue(0);

        builder.Property(e => e.VerifiedAt)
            .IsRequired()
            .HasColumnType("DATETIMEOFFSET");

        builder.Property(e => e.ExpiresAt)
            .HasColumnType("DATETIMEOFFSET");

        builder.HasIndex(e => e.MembershipId)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_VerificationLogs_Membership");

        builder.HasIndex(e => new { e.MembershipId, e.Purpose })
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_VerificationLogs_Membership_Purpose");

        builder.HasIndex(e => e.VerifiedAt)
            .IsDescending()
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_VerificationLogs_VerifiedAt");

        builder.HasOne(e => e.Membership)
            .WithMany(m => m.VerificationLogs)
            .HasForeignKey(e => e.MembershipId)
            .HasPrincipalKey(m => m.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired()
            .HasConstraintName("FK_VerificationLogs_Memberships");

        builder.HasOne(e => e.MobileNumber)
            .WithMany()
            .HasForeignKey(e => e.MobileNumberId)
            .HasPrincipalKey(mn => mn.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .IsRequired()
            .HasConstraintName("FK_VerificationLogs_MobileNumbers");

        builder.HasOne(e => e.Device)
            .WithMany()
            .HasForeignKey(e => e.DeviceId)
            .HasPrincipalKey(d => d.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .IsRequired()
            .HasConstraintName("FK_VerificationLogs_Devices");

        builder.HasOne(e => e.Account)
            .WithMany(a => a.VerificationLogs)
            .HasForeignKey(e => e.AccountId)
            .HasPrincipalKey(a => a.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .IsRequired(false)
            .HasConstraintName("FK_VerificationLogs_Accounts");
    }
}
