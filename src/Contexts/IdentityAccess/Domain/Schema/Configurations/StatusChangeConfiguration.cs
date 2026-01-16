using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.IdentityAccess.Domain.Schema.Configurations;

public class StatusChangeConfiguration : EntityBaseMap<StatusChangeEntity>
{
    public override void Map(EntityTypeBuilder<StatusChangeEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("status_changes");

        builder.Property(e => e.EntityType)
            .IsRequired()
            .HasMaxLength(64);

        builder.Property(e => e.EntityId)
            .IsRequired();

        builder.Property(e => e.PropertyName)
            .IsRequired()
            .HasMaxLength(64);

        builder.Property(e => e.FromValue)
            .HasMaxLength(100);

        builder.Property(e => e.ToValue)
            .HasMaxLength(100);

        builder.Property(e => e.ChangedAt)
            .HasDefaultValueSql("CURRENT_TIMESTAMP");

        builder.Property(e => e.Source)
            .HasMaxLength(100);

        builder.Property(e => e.Reason)
            .HasMaxLength(200);

        builder.Property(e => e.CorrelationId)
            .HasMaxLength(64);

        builder.Property(e => e.Metadata)
            .HasColumnType("jsonb");

        builder.HasIndex(e => new { e.EntityType, e.EntityId, e.ChangedAt })
            .IsDescending(false, false, true)
            .HasDatabaseName("IX_StatusChanges_Entity_ChangedAt");

        builder.HasIndex(e => e.ChangedAt)
            .IsDescending()
            .HasDatabaseName("IX_StatusChanges_ChangedAt");

        builder.HasIndex(e => new { e.EntityType, e.PropertyName, e.ToValue, e.ChangedAt })
            .IsDescending(false, false, false, true)
            .HasDatabaseName("IX_StatusChanges_ToValue");
    }
}
