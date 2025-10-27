using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema.Configurations;

public class DeviceContextConfiguration : EntityBaseMap<DeviceContextEntity>
{
    public override void Map(EntityTypeBuilder<DeviceContextEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("DeviceContexts");

        builder.Property(e => e.MembershipId)
            .IsRequired();

        builder.Property(e => e.DeviceId)
            .IsRequired();

        builder.Property(e => e.ContextEstablishedAt)
            .IsRequired()
            .HasDefaultValueSql("SYSDATETIMEOFFSET()");

        builder.Property(e => e.ContextExpiresAt)
            .IsRequired();

        builder.Property(e => e.LastActivityAt)
            .HasColumnType("DATETIMEOFFSET");

        builder.Property(e => e.IsActive)
            .HasDefaultValue(true);

        builder.HasIndex(e => new { e.MembershipId, e.DeviceId, e.IsActive })
            .IsUnique()
            .HasFilter("IsDeleted = 0 AND IsActive = 1")
            .HasDatabaseName("UX_DeviceContexts_Membership_Device_Active");

        builder.HasIndex(e => new { e.MembershipId, e.IsActive })
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_DeviceContexts_Membership_IsActive");

        builder.HasIndex(e => e.DeviceId)
            .HasFilter("IsDeleted = 0 AND IsActive = 1")
            .HasDatabaseName("IX_DeviceContexts_DeviceId_Active");

        builder.HasIndex(e => e.ContextExpiresAt)
            .HasFilter("IsDeleted = 0 AND IsActive = 1")
            .HasDatabaseName("IX_DeviceContexts_ExpiresAt");

        builder.HasIndex(e => new { e.ContextExpiresAt, e.IsActive })
            .HasFilter("IsDeleted = 0 AND IsActive = 1")
            .HasDatabaseName("IX_DeviceContexts_ExpiresAt_Cleanup");

        builder.HasIndex(e => new { e.MembershipId, e.LastActivityAt })
            .IsDescending(false, true)
            .HasFilter("IsDeleted = 0 AND IsActive = 1")
            .HasDatabaseName("IX_DeviceContexts_MembershipActivity");

        builder.ToTable(t => t.HasCheckConstraint("CHK_DeviceContexts_Expiry_Future",
            "ContextExpiresAt > ContextEstablishedAt"));

        builder.ToTable(t => t.HasCheckConstraint("CHK_DeviceContexts_Activity_Valid",
            "LastActivityAt IS NULL OR LastActivityAt >= ContextEstablishedAt"));

        Microsoft.EntityFrameworkCore.SqlServerIndexBuilderExtensions.IncludeProperties(
            builder.HasIndex(e => new { e.MembershipId, e.DeviceId })
                .HasFilter("IsDeleted = 0 AND IsActive = 1"),
            e => new { e.UniqueId, e.ActiveAccountId, e.ContextExpiresAt, e.LastActivityAt })
            .HasDatabaseName("IX_DeviceContexts_Active_Covering");

        builder.HasOne(e => e.Membership)
            .WithMany(m => m.DeviceContexts)
            .HasForeignKey(e => e.MembershipId)
            .HasPrincipalKey(m => m.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired()
            .HasConstraintName("FK_DeviceContexts_Memberships");

        builder.HasOne(e => e.Device)
            .WithMany()
            .HasForeignKey(e => e.DeviceId)
            .HasPrincipalKey(d => d.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired()
            .HasConstraintName("FK_DeviceContexts_Devices");

        builder.HasOne(e => e.ActiveAccount)
            .WithMany()
            .HasForeignKey(e => e.ActiveAccountId)
            .HasPrincipalKey(a => a.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .IsRequired(false)
            .HasConstraintName("FK_DeviceContexts_Accounts");
    }
}
