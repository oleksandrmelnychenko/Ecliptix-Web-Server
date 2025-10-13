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

        builder.Property(e => e.AccountUniqueId)
            .IsRequired();

        builder.Property(e => e.ConnectId)
            .IsRequired();

        builder.Property(e => e.Reason)
            .HasMaxLength(50)
            .IsRequired()
            .HasConversion<string>();

        builder.Property(e => e.LoggedOutAt)
            .IsRequired()
            .HasDefaultValueSql("GETUTCDATE()");

        builder.HasIndex(e => new { e.AccountUniqueId, e.LoggedOutAt })
            .IsDescending(false, true)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LogoutAudits_Account_LoggedOutAt");

        builder.HasIndex(e => e.ConnectId)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LogoutAudits_ConnectId");

        builder.HasIndex(e => e.LoggedOutAt)
            .IsDescending(true)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_LogoutAudits_LoggedOutAt");

        builder.HasOne(e => e.Membership)
            .WithMany()
            .HasForeignKey(e => e.AccountUniqueId)
            .HasPrincipalKey(m => m.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired()
            .HasConstraintName("FK_LogoutAudits_Memberships");
    }
}
