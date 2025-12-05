using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema.Configurations;

public class MembershipRelationConfiguration : EntityBaseMap<MembershipRelationEntity>
{
    public override void Map(EntityTypeBuilder<MembershipRelationEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("MembershipRelations");

        builder.HasKey(x => x.Id);

        builder.Property(x => x.InitiatorAccountId)
            .IsRequired();

        builder.Property(x => x.RecipientAccountId)
            .IsRequired();

        builder.Property(x => x.Status)
            .HasConversion(
                v => v == null ? null : v.ToString().ToLowerInvariant(),
                v => v == null ? null : Enum.Parse<ContactStatus>(v, true));

        builder.Property(x => x.Message)
            .HasMaxLength(512)
            .IsUnicode();

        builder.Property(x => x.MetaJson)
            .HasColumnType("text");

        builder.Property(x => x.MutedUntil)
            .IsRequired(false);

        builder.HasIndex(x => new { x.InitiatorAccountId, x.RecipientAccountId })
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_MembershipRelations_InitiatorRecipient");

        builder.HasIndex(x => new { x.RecipientAccountId, x.InitiatorAccountId })
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_MembershipRelations_RecipientInitiator");

        builder.HasOne(x => x.InitiatorAccount)
            .WithMany()
            .HasForeignKey(x => x.InitiatorAccountId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(x => x.RecipientAccount)
            .WithMany()
            .HasForeignKey(x => x.RecipientAccountId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
