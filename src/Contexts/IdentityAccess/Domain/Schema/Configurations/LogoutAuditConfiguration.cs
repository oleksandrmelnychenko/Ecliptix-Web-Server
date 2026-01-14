using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.IdentityAccess.Domain.Schema.Configurations;

public class LogoutAuditConfiguration : EntityBaseMap<LogoutAuditEntity>
{
    public override void Map(EntityTypeBuilder<LogoutAuditEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("logout_audits");

        builder.Property(e => e.MembershipId)
            .IsRequired();

        builder.Property(e => e.AccountId)
            .IsRequired(false);

        builder.Property(e => e.DeviceId)
            .IsRequired(false);

        builder.Property(e => e.Reason)
            .HasMaxLength(50)
            .IsRequired()
            .HasConversion<string>();

        builder.Property(e => e.IpAddress)
            .HasMaxLength(45);

        builder.Property(e => e.Platform)
            .HasMaxLength(50);

        builder.Property(e => e.LoggedOutAt)
            .IsRequired()
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        builder.HasIndex(e => new { e.MembershipId, e.LoggedOutAt })
            .IsDescending(false, true)
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_LogoutAudits_Membership_LoggedOutAt");

        builder.HasIndex(e => e.DeviceId)
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_LogoutAudits_DeviceId");

        builder.HasIndex(e => e.LoggedOutAt)
            .IsDescending(true)
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_LogoutAudits_LoggedOutAt");

        builder.HasOne(e => e.Membership)
            .WithMany()
            .HasForeignKey(e => e.MembershipId)
            .HasPrincipalKey(m => m.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired()
            .HasConstraintName("FK_LogoutAudits_Memberships");

        builder.HasOne(e => e.Account)
            .WithMany(a => a.LogoutAudits)
            .HasForeignKey(e => e.AccountId)
            .HasPrincipalKey(a => a.UniqueId)
            .OnDelete(DeleteBehavior.SetNull)
            .IsRequired(false)
            .HasConstraintName("FK_LogoutAudits_Accounts");

    }
}
