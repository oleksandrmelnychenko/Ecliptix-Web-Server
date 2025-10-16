using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Schema.Configurations;

public class LogoutAuditConfiguration : EntityBaseMap<LogoutAuditEntity>
{
    public override void Map(EntityTypeBuilder<LogoutAuditEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("LogoutAudits");

        builder.Property(e => e.MembershipUniqueId)
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
            .HasDefaultValueSql("SYSDATETIMEOFFSET()");

        builder.HasIndex(e => new { e.MembershipUniqueId, e.LoggedOutAt })
            .IsDescending(false, true)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LogoutAudits_Membership_LoggedOutAt");

        builder.HasIndex(e => e.DeviceId)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LogoutAudits_DeviceId");

        builder.HasIndex(e => e.LoggedOutAt)
            .IsDescending(true)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LogoutAudits_LoggedOutAt");

        builder.HasOne(e => e.Membership)
            .WithMany()
            .HasForeignKey(e => e.MembershipUniqueId)
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
