using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema.Configurations;

public class DeviceContextConfiguration : EntityBaseMap<DeviceContextEntity>
{
    private readonly string IsNotDeletedAndActiveFilter = "is_deleted = false AND is_active = true";
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
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        builder.Property(e => e.ContextExpiresAt)
            .IsRequired();

        builder.Property(e => e.LastActivityAt)
            .HasColumnType("timestamp with time zone");

        builder.Property(e => e.IsActive)
            .HasDefaultValue(true);

        builder.HasIndex(e => new { e.MembershipId, e.DeviceId, e.IsActive })
            .IsUnique()
            .HasFilter(IsNotDeletedAndActiveFilter)
            .HasDatabaseName("UX_DeviceContexts_Membership_Device_Active");

        builder.HasIndex(e => new { e.MembershipId, e.IsActive })
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_DeviceContexts_Membership_IsActive");

        builder.HasIndex(e => e.DeviceId)
            .HasFilter(IsNotDeletedAndActiveFilter)
            .HasDatabaseName("IX_DeviceContexts_DeviceId_Active");

        builder.HasIndex(e => e.ContextExpiresAt)
            .HasFilter(IsNotDeletedAndActiveFilter)
            .HasDatabaseName("IX_DeviceContexts_ExpiresAt");

        builder.HasIndex(e => new { e.ContextExpiresAt, e.IsActive })
            .HasFilter(IsNotDeletedAndActiveFilter)
            .HasDatabaseName("IX_DeviceContexts_ExpiresAt_Cleanup");

        builder.HasIndex(e => new { e.MembershipId, e.LastActivityAt })
            .IsDescending(false, true)
            .HasFilter(IsNotDeletedAndActiveFilter)
            .HasDatabaseName("IX_DeviceContexts_MembershipActivity");

        builder.ToTable(t => t.HasCheckConstraint("CHK_DeviceContexts_Expiry_Future",
            "context_expires_at > context_established_at"));

        builder.ToTable(t => t.HasCheckConstraint("CHK_DeviceContexts_Activity_Valid",
            "last_activity_at IS NULL OR last_activity_at >= context_established_at"));

        builder.HasIndex(e => new { e.MembershipId, e.DeviceId })
            .HasFilter("is_deleted = false AND is_active = true")
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
            .HasPrincipalKey(d => d.DeviceId)
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
