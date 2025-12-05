using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Domain.Schema.ValueConverters;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema.Configurations;

public class VerificationFlowConfiguration : EntityBaseMap<VerificationFlowEntity>
{
    public override void Map(EntityTypeBuilder<VerificationFlowEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("VerificationFlows");

        builder.Property(e => e.MobileNumberId)
            .IsRequired();

        builder.Property(e => e.AppDeviceId)
            .IsRequired();

        builder.Property(e => e.Status)
            .IsRequired()
            .HasMaxLength(20)
            .HasDefaultValue(VerificationFlowStatus.Pending)
            .HasConversion(new EnumToSnakeCaseConverter<VerificationFlowStatus>());

        builder.Property(e => e.Purpose)
            .IsRequired()
            .HasMaxLength(30)
            .HasDefaultValue(VerificationPurpose.Unspecified)
            .HasConversion(new EnumToSnakeCaseConverter<VerificationPurpose>());

        builder.Property(e => e.OtpCount)
            .HasDefaultValue((short)0);

        builder.Property(e => e.LastOtpSentAt)
            .IsRequired(false);

        builder.Property(e => e.ExpiresAt)
            .IsRequired();

        builder.ToTable(t => t.HasCheckConstraint("CHK_VerificationFlows_Status",
            "status IN ('pending', 'verified', 'expired', 'failed')"));

        builder.ToTable(t => t.HasCheckConstraint("CHK_VerificationFlows_Purpose",
            "purpose IN ('unspecified', 'registration', 'login', 'password_recovery', 'update_phone')"));

        builder.HasIndex(e => e.MobileNumberId)
            .HasDatabaseName("IX_VerificationFlows_MobileNumberId");

        builder.HasIndex(e => e.AppDeviceId)
            .HasDatabaseName("IX_VerificationFlows_AppDeviceId");

        builder.HasIndex(e => e.Status)
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_VerificationFlows_Status");

        builder.HasIndex(e => e.ExpiresAt)
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_VerificationFlows_ExpiresAt");

        builder.HasIndex(e => new { e.UniqueId, e.LastOtpSentAt, e.OtpCount, e.ExpiresAt })
            .HasFilter("is_deleted = false AND status = 'pending'")
            .HasDatabaseName("IX_VerificationFlows_CooldownCheck");

        builder.HasOne(e => e.MobileNumber)
            .WithMany(p => p.VerificationFlows)
            .HasForeignKey(e => e.MobileNumberId)
            .HasPrincipalKey(p => p.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_VerificationFlows_MobileNumbers");

        builder.HasOne(e => e.AppDevice)
            .WithMany(d => d.VerificationFlows)
            .HasForeignKey(e => e.AppDeviceId)
            .HasPrincipalKey(d => d.DeviceId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_VerificationFlows_Devices");
    }
}
