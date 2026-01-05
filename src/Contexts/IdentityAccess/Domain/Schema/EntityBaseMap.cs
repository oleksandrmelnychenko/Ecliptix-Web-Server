using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.IdentityAccess.Domain.Schema;

public abstract class EntityBaseMap<T> : EntityTypeConfiguration<T> where T : EntityBase
{
    public override void Map(EntityTypeBuilder<T> entity)
    {
        entity.HasKey(e => e.Id);
        entity.Property(e => e.Id).UseIdentityColumn();

        entity.Property(e => e.UniqueId).HasDefaultValueSql("gen_random_uuid()");

        entity.Property(e => e.CreatedAt).HasDefaultValueSql("CURRENT_TIMESTAMP");
        entity.Property(e => e.UpdatedAt).HasDefaultValueSql("CURRENT_TIMESTAMP");
        entity.Property(e => e.IsDeleted).HasDefaultValue(false);

        entity.Property(e => e.RowVersion)
            .IsRowVersion()
            .IsConcurrencyToken()
            .HasDefaultValue(new byte[] { 0 })
            .ValueGeneratedOnAddOrUpdate();

        entity.HasQueryFilter(e => !e.IsDeleted);

        ConfigureIndexes(entity);
    }

    protected virtual void ConfigureIndexes(EntityTypeBuilder<T> builder)
    {

        builder.HasIndex(e => e.UniqueId)
            .IsUnique()
            .HasDatabaseName($"UQ_{typeof(T).Name}_UniqueId");

    }
}
