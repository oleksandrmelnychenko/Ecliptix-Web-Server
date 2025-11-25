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

        builder.HasIndex(x => x.InitiatorAccountId)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_MembershipRelations_InitiatorAccountId");
            
        builder.HasIndex(x => x.RecipientAccountId)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_MembershipRelations_RecipientAccountId");
        
        builder.HasIndex(x => x.Status)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_MembershipRelations_Status");

        builder.HasIndex(x => new { x.InitiatorAccountId, x.RecipientAccountId })
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_MembershipRelations_InitiatorRecipient");

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
