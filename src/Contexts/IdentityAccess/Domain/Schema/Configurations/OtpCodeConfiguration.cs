using Ecliptix.IdentityAccess.Domain.Memberships.Otp;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.IdentityAccess.Domain.Schema.ValueConverters;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.IdentityAccess.Domain.Schema.Configurations;

public class OtpCodeConfiguration : EntityBaseMap<OtpCodeEntity>
{
    public override void Map(EntityTypeBuilder<OtpCodeEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("otp_codes");

        builder.Property(e => e.VerificationFlowId)
            .IsRequired();

        builder.Property(e => e.OtpValue)
            .IsRequired()
            .HasMaxLength(64);

        builder.Property(e => e.OtpSalt)
            .IsRequired()
            .HasMaxLength(32);

        builder.Property(e => e.Status)
            .IsRequired()
            .HasMaxLength(20)
            .HasDefaultValue(OtpStatus.Active)
            .HasConversion(new EnumToSnakeCaseConverter<OtpStatus>());

        builder.Property(e => e.AttemptCount)
            .HasDefaultValue((short)0);

        builder.Property(e => e.ExpiresAt)
            .IsRequired();

        builder.ToTable(t => t.HasCheckConstraint("CHK_OtpCodes_Status",
            "status IN ('active', 'used', 'expired', 'invalid')"));

        builder.HasIndex(e => e.VerificationFlowId)
            .HasDatabaseName("IX_OtpCodes_VerificationFlowId");

        builder.HasIndex(e => e.Status)
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_OtpCodes_Status");

        builder.HasIndex(e => e.ExpiresAt)
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_OtpCodes_ExpiresAt");

        builder.HasOne(e => e.VerificationFlow)
            .WithMany(v => v.OtpCodes)
            .HasForeignKey(e => e.VerificationFlowId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_OtpCodes_VerificationFlows");
    }
}
