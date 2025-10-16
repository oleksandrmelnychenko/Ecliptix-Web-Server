using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Schema.Configurations;

public class FailedOtpAttemptConfiguration : EntityBaseMap<FailedOtpAttemptEntity>
{
    public override void Map(EntityTypeBuilder<FailedOtpAttemptEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("FailedOtpAttempts");

        builder.Property(e => e.OtpRecordId)
            .IsRequired();

        builder.Property(e => e.AttemptedValue)
            .IsRequired()
            .HasMaxLength(10);

        builder.Property(e => e.FailureReason)
            .IsRequired()
            .HasMaxLength(50);

        builder.Property(e => e.AttemptedAt)
            .HasDefaultValueSql("SYSDATETIMEOFFSET()");

        builder.HasIndex(e => e.OtpRecordId)
            .HasDatabaseName("IX_FailedOtpAttempts_OtpRecordId");

        builder.HasIndex(e => e.AttemptedAt)
            .IsDescending()
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_FailedOtpAttempts_AttemptedAt");

        builder.HasOne(e => e.OtpRecord)
            .WithMany(o => o.FailedAttempts)
            .HasForeignKey(e => e.OtpRecordId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_FailedOtpAttempts_OtpCodes");
    }
}
