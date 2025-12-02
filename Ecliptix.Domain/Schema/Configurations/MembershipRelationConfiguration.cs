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
            .HasConversion<string>()
            .IsRequired();

        builder.Property(x => x.Message)
            .HasMaxLength(512)
            .IsUnicode();

        builder.Property(x => x.MetaJson)
            .HasColumnType("nvarchar(max)");

        builder.Property(x => x.MutedUntil)
            .IsRequired(false);

        IndexBuilder<MembershipRelationEntity> initiatorIdx = builder.HasIndex(x => new { x.InitiatorAccountId, x.RecipientAccountId })
            .HasFilter("[IsDeleted] = 0");
        SqlServerIndexBuilderExtensions.IncludeProperties(initiatorIdx, nameof(MembershipRelationEntity.Status), nameof(MembershipRelationEntity.Message), nameof(MembershipRelationEntity.CreatedAt), nameof(MembershipRelationEntity.MutedUntil));
        initiatorIdx.HasDatabaseName("IX_MembershipRelations_InitiatorRecipient_Covering");

        IndexBuilder<MembershipRelationEntity> recipientIdx = builder.HasIndex(x => new { x.RecipientAccountId, x.InitiatorAccountId })
            .HasFilter("[IsDeleted] = 0");
        SqlServerIndexBuilderExtensions.IncludeProperties(recipientIdx, nameof(MembershipRelationEntity.Status), nameof(MembershipRelationEntity.Message), nameof(MembershipRelationEntity.CreatedAt), nameof(MembershipRelationEntity.MutedUntil));
        recipientIdx.HasDatabaseName("IX_MembershipRelations_RecipientInitiator_Covering");

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
