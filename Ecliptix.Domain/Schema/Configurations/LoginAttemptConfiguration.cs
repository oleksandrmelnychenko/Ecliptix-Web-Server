using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema.Configurations;

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
            .HasDefaultValueSql("SYSDATETIMEOFFSET()");

        builder.Property(e => e.CompletedAt)
            .HasColumnType("DATETIMEOFFSET");

        builder.Property(e => e.LockedUntil)
            .HasColumnType("DATETIMEOFFSET");

        builder.ToTable(t => t.HasCheckConstraint("CHK_LoginAttempts_Success_CompletedAt",
            "(IsSuccess = 0) OR (CompletedAt IS NOT NULL)"));

        builder.ToTable(t => t.HasCheckConstraint("CHK_LoginAttempts_LockedUntil_Future",
            "LockedUntil IS NULL OR LockedUntil > AttemptedAt"));

        builder.HasIndex(e => new { e.MembershipUniqueId, e.AttemptedAt })
            .IsDescending(false, true)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LoginAttempts_Membership_AttemptedAt");

        builder.HasIndex(e => e.MobileNumber)
            .HasFilter("IsDeleted = 0 AND MobileNumber IS NOT NULL")
            .HasDatabaseName("IX_LoginAttempts_MobileNumber");

        builder.HasIndex(e => new { e.MobileNumber, e.AttemptedAt, e.IsSuccess, e.LockedUntil })
            .IsDescending(false, true, false, false)
            .HasFilter("IsDeleted = 0 AND LockedUntil IS NULL AND MobileNumber IS NOT NULL")
            .HasDatabaseName("IX_LoginAttempts_RateLimiting_Optimized");

        builder.HasIndex(e => new { e.DeviceId, e.AttemptedAt, e.IsSuccess })
            .IsDescending(false, true, false)
            .HasFilter("IsDeleted = 0 AND DeviceId IS NOT NULL")
            .HasDatabaseName("IX_LoginAttempts_DeviceRateLimiting");

        builder.HasIndex(e => new { e.MobileNumber, e.LockedUntil })
            .HasFilter("IsDeleted = 0 AND LockedUntil IS NOT NULL")
            .HasDatabaseName("IX_LoginAttempts_Lockout");

        builder.HasIndex(e => e.IsSuccess)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LoginAttempts_IsSuccess");

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
            .HasPrincipalKey(d => d.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .IsRequired(false)
            .HasConstraintName("FK_LoginAttempts_Devices");
    }
}
