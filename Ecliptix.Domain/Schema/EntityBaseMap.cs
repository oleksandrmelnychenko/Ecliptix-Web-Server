using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema;

public abstract class EntityBaseMap<T> : EntityTypeConfiguration<T> where T : EntityBase
{
    public override void Map(EntityTypeBuilder<T> entity)
    {
        entity.HasKey(e => e.Id);
        entity.Property(e => e.Id).UseIdentityColumn();

        entity.Property(e => e.UniqueId).HasDefaultValueSql("NEWID()");

        entity.Property(e => e.CreatedAt).HasDefaultValueSql("SYSDATETIMEOFFSET()");
        entity.Property(e => e.UpdatedAt).HasDefaultValueSql("SYSDATETIMEOFFSET()");
        entity.Property(e => e.IsDeleted).HasDefaultValue(false);

        entity.Property(e => e.RowVersion)
            .IsRowVersion()
            .IsConcurrencyToken();

        entity.HasQueryFilter(e => !e.IsDeleted);

        ConfigureIndexes(entity);
    }

    protected virtual void ConfigureIndexes(EntityTypeBuilder<T> builder)
    {
        builder.HasIndex(e => e.UniqueId)
            .IsUnique()
            .HasDatabaseName($"UQ_{typeof(T).Name}_UniqueId");

        builder.HasIndex(e => e.CreatedAt)
            .IsDescending()
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName($"IX_{typeof(T).Name}_CreatedAt");

        builder.HasIndex(e => e.UpdatedAt)
            .IsDescending()
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName($"IX_{typeof(T).Name}_UpdatedAt");
    }
}
