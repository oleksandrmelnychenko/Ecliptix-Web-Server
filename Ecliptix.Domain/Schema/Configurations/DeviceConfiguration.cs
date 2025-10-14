using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Schema.Configurations;

public class DeviceConfiguration : EntityBaseMap<DeviceEntity>
{
    public override void Map(EntityTypeBuilder<DeviceEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("Devices");

        builder.Property(e => e.AppInstanceId)
            .IsRequired();

        builder.Property(e => e.DeviceType)
            .HasDefaultValue(1);

        builder.HasIndex(e => e.AppInstanceId)
            .HasDatabaseName("IX_Devices_AppInstanceId");

        builder.HasIndex(e => e.DeviceType)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_Devices_DeviceType");
    }
}
