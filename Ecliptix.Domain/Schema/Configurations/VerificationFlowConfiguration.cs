using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ecliptix.Domain.Schema.Entities;

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
            .HasDefaultValue("pending");

        builder.Property(e => e.Purpose)
            .IsRequired()
            .HasMaxLength(30)
            .HasDefaultValue("unspecified");

        builder.Property(e => e.OtpCount)
            .HasDefaultValue((short)0);

        builder.Property(e => e.LastOtpSentAt)
            .IsRequired(false);

        builder.Property(e => e.ExpiresAt)
            .IsRequired();

        builder.ToTable(t => t.HasCheckConstraint("CHK_VerificationFlows_Status",
            "Status IN ('pending', 'verified', 'expired', 'failed')"));

        builder.ToTable(t => t.HasCheckConstraint("CHK_VerificationFlows_Purpose",
            "Purpose IN ('unspecified', 'registration', 'login', 'password_recovery', 'update_phone')"));

        builder.HasIndex(e => e.MobileNumberId)
            .HasDatabaseName("IX_VerificationFlows_MobileNumberId");

        builder.HasIndex(e => e.AppDeviceId)
            .HasDatabaseName("IX_VerificationFlows_AppDeviceId");

        builder.HasIndex(e => e.Status)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_VerificationFlows_Status");

        builder.HasIndex(e => e.ExpiresAt)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_VerificationFlows_ExpiresAt");

        Microsoft.EntityFrameworkCore.SqlServerIndexBuilderExtensions.IncludeProperties(
            builder.HasIndex(e => new { e.MobileNumberId, e.AppDeviceId, e.Purpose, e.Status, e.ExpiresAt })
                .HasFilter("IsDeleted = 0 AND Status = 'pending'"),
            e => new { e.UniqueId, e.ConnectionId, e.OtpCount, e.CreatedAt, e.UpdatedAt })
            .HasDatabaseName("IX_VerificationFlows_ActiveFlowRecovery");

        builder.HasIndex(e => new { e.UniqueId, e.LastOtpSentAt, e.OtpCount, e.ExpiresAt })
            .HasFilter("IsDeleted = 0 AND Status = 'pending'")
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
            .HasPrincipalKey(d => d.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_VerificationFlows_Devices");
    }
}
