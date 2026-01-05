using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.IdentityAccess.Domain.Schema.Configurations;

public class LoginAttemptConfiguration : EntityBaseMap<LoginAttemptEntity>
{
    public override void Map(EntityTypeBuilder<LoginAttemptEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("LoginAttempts");

        builder.Property(e => e.MembershipUniqueId)
            .IsRequired(false);

        builder.Property(e => e.AccountId)
            .IsRequired(false);

        builder.Property(e => e.DeviceId)
            .IsRequired(false);

        builder.Property(e => e.MobileNumber)
            .HasMaxLength(18);

        builder.Property(e => e.Outcome)
            .HasMaxLength(200);

        builder.Property(e => e.IsSuccess)
            .HasDefaultValue(false);

        builder.Property(e => e.ErrorMessage)
            .HasMaxLength(500);

        builder.Property(e => e.IpAddress)
            .HasMaxLength(45);

        builder.Property(e => e.Platform)
            .HasMaxLength(50);

        builder.Property(e => e.AttemptedAt)
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        builder.Property(e => e.CompletedAt)
            .HasColumnType("timestamp with time zone");

        builder.Property(e => e.LockedUntil)
            .HasColumnType("timestamp with time zone");

        builder.ToTable(t => t.HasCheckConstraint("CHK_LoginAttempts_Success_CompletedAt",
            "(is_success = false) OR (completed_at IS NOT NULL)"));

        builder.ToTable(t => t.HasCheckConstraint("CHK_LoginAttempts_LockedUntil_Future",
            "locked_until IS NULL OR locked_until > attempted_at"));

        IndexBuilder<LoginAttemptEntity> lockoutIdx = builder.HasIndex(e => new { e.MobileNumber, e.LockedUntil, e.AttemptedAt })
            .IsDescending(false, false, true)
            .HasFilter("is_deleted = false AND locked_until IS NOT NULL");

        builder.HasIndex(e => new { e.MobileNumber, e.AttemptedAt, e.IsSuccess })
            .IsDescending(false, false, false)
            .HasFilter("is_deleted = false AND is_success = false AND locked_until IS NULL")
            .HasDatabaseName("IX_LoginAttempts_CountFailed");

        builder.HasIndex(e => new { e.MembershipUniqueId, e.Outcome, e.AttemptedAt })
            .IsDescending(false, false, false)
            .HasFilter("is_deleted = false AND is_success = false AND outcome = 'membership_creation'")
            .HasDatabaseName("IX_LoginAttempts_MembershipCreation");

        IndexBuilder<LoginAttemptEntity> deviceIdx = builder.HasIndex(e => new { e.DeviceId, e.AttemptedAt })
            .IsDescending(false, true)
            .HasFilter("is_deleted = false AND device_id IS NOT NULL");

        builder.HasOne(e => e.Membership)
            .WithMany(m => m.LoginAttempts)
            .HasForeignKey(e => e.MembershipUniqueId)
            .HasPrincipalKey(m => m.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired(false)
            .HasConstraintName("FK_LoginAttempts_Memberships");

        builder.HasOne(e => e.Account)
            .WithMany(a => a.LoginAttempts)
            .HasForeignKey(e => e.AccountId)
            .HasPrincipalKey(a => a.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .IsRequired(false)
            .HasConstraintName("FK_LoginAttempts_Accounts");

        builder.HasOne(e => e.Device)
            .WithMany()
            .HasForeignKey(e => e.DeviceId)
            .HasPrincipalKey(d => d.DeviceId)
            .OnDelete(DeleteBehavior.NoAction)
            .IsRequired(false)
            .HasConstraintName("FK_LoginAttempts_Devices");
    }
}
