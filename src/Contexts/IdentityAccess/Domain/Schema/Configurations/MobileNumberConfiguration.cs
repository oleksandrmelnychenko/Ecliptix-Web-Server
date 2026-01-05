using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.IdentityAccess.Domain.Schema.Configurations;

public class MobileNumberConfiguration : EntityBaseMap<MobileNumberEntity>
{
    public override void Map(EntityTypeBuilder<MobileNumberEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("MobileNumbers");

        builder.Property(e => e.Number)
            .IsRequired()
            .HasMaxLength(18);

        builder.Property(e => e.Region)
            .HasMaxLength(2);

        builder.HasIndex(e => e.Number)
            .IsUnique()
            .HasDatabaseName("UQ_MobileNumbers_Number");

        builder.HasIndex(e => new { e.Number, e.Region, e.IsDeleted })
            .IsUnique()
            .HasDatabaseName("UQ_MobileNumbers_ActiveNumberRegion");

        builder.HasIndex(e => new { e.Number, e.Region })
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_MobileNumbers_MobileNumber_Region");

        builder.HasIndex(e => e.Region)
            .HasFilter("is_deleted = false AND Region IS NOT NULL")
            .HasDatabaseName("IX_MobileNumbers_Region");

        builder.HasIndex(e => e.CreatedAt)
            .IsDescending()
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_MobileNumbers_CreatedAt");
    }
}
