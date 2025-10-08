using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Schema.Configurations;

public class LoginAttemptConfiguration : EntityBaseMap<LoginAttempt>
{
    public override void Map(EntityTypeBuilder<LoginAttempt> builder)
    {
        base.Map(builder);

        builder.ToTable("LoginAttempts");

        builder.Property(e => e.MobileNumber)
            .HasMaxLength(18);

        builder.Property(e => e.Outcome)
            .HasMaxLength(200);

        builder.Property(e => e.IsSuccess)
            .HasDefaultValue(false);

        builder.Property(e => e.Timestamp)
            .HasDefaultValueSql("GETUTCDATE()");

        builder.Property(e => e.LockedUntil)
            .HasColumnType("DATETIME2");

        builder.Property(e => e.Status)
            .HasMaxLength(20);

        builder.Property(e => e.ErrorMessage)
            .HasMaxLength(500);

        builder.Property(e => e.SessionId)
            .HasMaxLength(64);

        builder.Property(e => e.AttemptedAt)
            .HasDefaultValueSql("GETUTCDATE()");

        builder.HasIndex(e => new { e.MembershipUniqueId, e.AttemptedAt })
            .IsDescending(false, true)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LoginAttempts_Membership_AttemptedAt");

        builder.HasIndex(e => e.Status)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LoginAttempts_Status");

        builder.HasIndex(e => e.SessionId)
            .HasFilter("IsDeleted = 0 AND SessionId IS NOT NULL")
            .HasDatabaseName("IX_LoginAttempts_SessionId");

        builder.HasIndex(e => e.MobileNumber)
            .HasFilter("IsDeleted = 0 AND MobileNumber IS NOT NULL")
            .HasDatabaseName("IX_LoginAttempts_MobileNumber");

        Microsoft.EntityFrameworkCore.SqlServerIndexBuilderExtensions.IncludeProperties(
            builder.HasIndex(e => new { e.MobileNumber, e.Timestamp })
                .IsDescending(false, true)
                .HasFilter("IsDeleted = 0 AND MobileNumber IS NOT NULL AND LockedUntil IS NULL"),
            e => e.IsSuccess)
            .HasDatabaseName("IX_LoginAttempts_RateLimiting");

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
    }
}