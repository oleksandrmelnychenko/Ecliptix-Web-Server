using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Schema.Configurations;

public class LoginAttemptConfiguration : EntityBaseMap<LoginAttemptEntity>
{
    public override void Map(EntityTypeBuilder<LoginAttemptEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("LoginAttempts");

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

        builder.HasIndex(e => new { e.AccountId, e.AttemptedAt })
            .IsDescending(false, true)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LoginAttempts_Account_AttemptedAt");

        builder.HasIndex(e => e.Status)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LoginAttempts_Status");

        builder.HasIndex(e => e.SessionId)
            .HasFilter("IsDeleted = 0 AND SessionId IS NOT NULL")
            .HasDatabaseName("IX_LoginAttempts_SessionId");

        builder.HasIndex(e => e.MobileNumberId)
            .HasFilter("IsDeleted = 0 AND MobileNumberId IS NOT NULL")
            .HasDatabaseName("IX_LoginAttempts_MobileNumberId");

        SqlServerIndexBuilderExtensions.IncludeProperties(
            builder.HasIndex(e => new { e.MobileNumberId, e.Timestamp })
                .IsDescending(false, true)
                .HasFilter("IsDeleted = 0 AND MobileNumberId IS NOT NULL AND LockedUntil IS NULL"),
            e => e.IsSuccess)
            .HasDatabaseName("IX_LoginAttempts_RateLimiting");

        builder.HasIndex(e => new { e.MobileNumberId, e.LockedUntil })
            .HasFilter("IsDeleted = 0 AND LockedUntil IS NOT NULL")
            .HasDatabaseName("IX_LoginAttempts_Lockout");

        builder.HasIndex(e => e.IsSuccess)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LoginAttempts_IsSuccess");

        builder.HasOne(e => e.Account)
            .WithMany(a => a.LoginAttempts)
            .HasForeignKey(e => e.AccountId)
            .HasPrincipalKey(a => a.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired()
            .HasConstraintName("FK_LoginAttempts_Accounts");
        
        builder.HasOne(e => e.MobileNumber)
            .WithMany()
            .HasForeignKey(e => e.MobileNumberId)
            .HasPrincipalKey(m => m.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .IsRequired(false)
            .HasConstraintName("FK_LoginAttempts_MobileNumbers");
    }
}