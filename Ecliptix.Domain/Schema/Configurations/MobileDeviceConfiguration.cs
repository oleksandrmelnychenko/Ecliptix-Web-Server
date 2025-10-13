using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Schema.Configurations;

public class MobileDeviceConfiguration : EntityBaseMap<MobileDeviceEntity>
{
    public override void Map(EntityTypeBuilder<MobileDeviceEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("MobileDevices");

        builder.Property(e => e.AccountId).IsRequired();
        builder.Property(e => e.DeviceId).IsRequired();

        builder.Property(e => e.RelationshipType)
            .HasMaxLength(50)
            .HasDefaultValue("primary");

        builder.Property(e => e.IsActive)
            .HasDefaultValue(true);

        builder.HasIndex(e => new { e.AccountId, e.DeviceId })
            .IsUnique()
            .HasDatabaseName("UQ_MobileDevices_AccountDevice");

        builder.HasIndex(e => e.AccountId)
            .HasDatabaseName("IX_MobileDevices_AccountId");

        builder.HasIndex(e => e.IsActive)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_MobileDevices_IsActive");

        builder.HasIndex(e => e.LastUsedAt)
            .IsDescending()
            .HasFilter("IsDeleted = 0 AND LastUsedAt IS NOT NULL")
            .HasDatabaseName("IX_MobileDevices_LastUsedAt");

        builder.HasOne(e => e.Account)
            .WithMany(a => a.MobileDevices)
            .HasForeignKey(e => e.AccountId)
            .HasPrincipalKey(a => a.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_MobileDevices_Accounts");

        builder.HasOne(e => e.Device)
            .WithMany(d => d.MobileDevices)
            .HasForeignKey(e => e.DeviceId)
            .HasPrincipalKey(a => a.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_MobileDevices_Devices");
    }
}