using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Schema.Configurations;

public class MobileDeviceConfiguration : EntityBaseMap<MobileDevice>
{
    public override void Map(EntityTypeBuilder<MobileDevice> builder)
    {
        base.Map(builder);

        builder.ToTable("MobileDevices");

        builder.Property(e => e.MobileNumberId)
            .IsRequired();

        builder.Property(e => e.DeviceId)
            .IsRequired();

        builder.Property(e => e.RelationshipType)
            .HasMaxLength(50)
            .HasDefaultValue("primary");

        builder.Property(e => e.IsActive)
            .HasDefaultValue(true);

        builder.HasIndex(e => new { e.MobileNumberId, e.DeviceId })
            .IsUnique()
            .HasDatabaseName("UQ_MobileDevices_PhoneDevice");

        builder.HasIndex(e => e.MobileNumberId)
            .HasDatabaseName("IX_MobileDevices_MobileNumberId");

        builder.HasIndex(e => e.DeviceId)
            .HasDatabaseName("IX_MobileDevices_DeviceId");

        builder.HasIndex(e => e.IsActive)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_MobileDevices_IsActive");

        builder.HasIndex(e => e.LastUsedAt)
            .IsDescending()
            .HasFilter("IsDeleted = 0 AND LastUsedAt IS NOT NULL")
            .HasDatabaseName("IX_MobileDevices_LastUsedAt");

        builder.HasOne(e => e.MobileNumber)
            .WithMany(p => p.MobileDevices)
            .HasForeignKey(e => e.MobileNumberId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_MobileDevices_MobileNumbers");

        builder.HasOne(e => e.Device)
            .WithMany(d => d.MobileDevices)
            .HasForeignKey(e => e.DeviceId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_MobileDevices_Devices");
    }
}