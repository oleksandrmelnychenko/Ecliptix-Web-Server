using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.IdentityAccess.Domain.Schema.Configurations;

public class FailedOtpAttemptConfiguration : EntityBaseMap<FailedOtpAttemptEntity>
{
    public override void Map(EntityTypeBuilder<FailedOtpAttemptEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("failed_otp_attempts");

        builder.Property(e => e.OtpCodeId)
            .IsRequired();

        builder.Property(e => e.AttemptedValue)
            .IsRequired()
            .HasMaxLength(10);

        builder.Property(e => e.FailureReason)
            .IsRequired()
            .HasMaxLength(50);

        builder.Property(e => e.AttemptedAt)
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        builder.HasIndex(e => e.OtpCodeId)
            .HasDatabaseName("IX_FailedOtpAttempts_OtpCodeId");

        builder.HasIndex(e => e.AttemptedAt)
            .IsDescending()
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_FailedOtpAttempts_AttemptedAt");

        builder.HasOne(e => e.OtpCode)
            .WithMany(o => o.FailedAttempts)
            .HasForeignKey(e => e.OtpCodeId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_FailedOtpAttempts_OtpCodes");
    }
}
