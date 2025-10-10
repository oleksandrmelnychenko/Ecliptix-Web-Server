using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Schema.Configurations;

public class MobileNumberConfiguration : EntityBaseMap<MobileNumber>
{
    public override void Map(EntityTypeBuilder<MobileNumber> builder)
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
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_MobileNumbers_MobileNumber_Region");

        builder.HasIndex(e => e.Region)
            .HasFilter("IsDeleted = 0 AND Region IS NOT NULL")
            .HasDatabaseName("IX_MobileNumbers_Region");

        builder.HasIndex(e => e.CreatedAt)
            .IsDescending()
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_MobileNumbers_CreatedAt");
    }
}