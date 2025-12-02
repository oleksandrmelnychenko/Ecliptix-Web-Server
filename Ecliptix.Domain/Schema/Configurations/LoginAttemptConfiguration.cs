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

        IndexBuilder<LoginAttemptEntity> lockoutIdx = builder.HasIndex(e => new { e.MobileNumber, e.LockedUntil, e.AttemptedAt })
            .IsDescending(false, false, true)
            .HasFilter("[IsDeleted] = 0 AND [LockedUntil] IS NOT NULL");
        SqlServerIndexBuilderExtensions.IncludeProperties(lockoutIdx, nameof(LoginAttemptEntity.Id), nameof(LoginAttemptEntity.Outcome), nameof(LoginAttemptEntity.ErrorMessage));
        lockoutIdx.HasDatabaseName("IX_LoginAttempts_Lockout_Covering");

        builder.HasIndex(e => new { e.MobileNumber, e.AttemptedAt, e.IsSuccess })
            .IsDescending(false, false, false)
            .HasFilter("[IsDeleted] = 0 AND [IsSuccess] = 0 AND [LockedUntil] IS NULL")
            .HasDatabaseName("IX_LoginAttempts_CountFailed");

        builder.HasIndex(e => new { e.MembershipUniqueId, e.Outcome, e.AttemptedAt })
            .IsDescending(false, false, false)
            .HasFilter("[IsDeleted] = 0 AND [IsSuccess] = 0 AND [Outcome] = 'membership_creation'")
            .HasDatabaseName("IX_LoginAttempts_MembershipCreation");

        IndexBuilder<LoginAttemptEntity> deviceIdx = builder.HasIndex(e => new { e.DeviceId, e.AttemptedAt })
            .IsDescending(false, true)
            .HasFilter("[IsDeleted] = 0 AND [DeviceId] IS NOT NULL");
        SqlServerIndexBuilderExtensions.IncludeProperties(deviceIdx, e => e.IsSuccess);
        deviceIdx.HasDatabaseName("IX_LoginAttempts_Device");

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
