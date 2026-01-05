using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.IdentityAccess.Domain.Schema.Configurations;

public class DeviceConfiguration : EntityBaseMap<DeviceEntity>
{
    public override void Map(EntityTypeBuilder<DeviceEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("Devices");

        builder.Property(e => e.AppInstanceId)
            .IsRequired();

        builder.Property(e => e.DeviceId)
            .IsRequired();

        builder.Property(e => e.DeviceType)
            .HasDefaultValue(1);

        builder.HasIndex(e => e.AppInstanceId)
            .IsUnique()
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_Devices_AppInstanceId");

        builder.HasIndex(e => e.DeviceId)
            .IsUnique()
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_Devices_DeviceId");

        builder.HasIndex(e => e.DeviceType)
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_Devices_DeviceType");
    }
}
