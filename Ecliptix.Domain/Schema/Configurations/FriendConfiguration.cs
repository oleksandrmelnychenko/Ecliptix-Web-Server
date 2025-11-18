using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema.Configurations;

public class FriendConfiguration : EntityBaseMap<FriendEntity>
{
    public override void Map(EntityTypeBuilder<FriendEntity> builder)
    {
        base.Map(builder);
        
        builder.ToTable("FriendRelations");

        builder.HasKey(x => x.Id);

        builder.Property(x => x.UserAId)
            .IsRequired();
        
        builder.Property(x => x.UserBId)
            .IsRequired();
        
        builder.Property(x => x.RequestedById)
            .IsRequired();
        
        builder.Property(x => x.Status)
            .HasConversion<string>()
            .IsRequired();
        
        builder.Property(x => x.Message)
            .HasMaxLength(512)
            .IsUnicode();
        
        builder.Property(x => x.MetaJson)
            .HasColumnType("nvarchar(max)");
        
        builder.Property(x => x.AcceptedAt);

        builder.HasIndex(x => new { x.UserAId })
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_Accounts_UserAId");
            
        builder.HasIndex(x => new { x.UserBId })
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_Accounts_UserBId");
        
        builder.HasIndex(x => new { x.Status })
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_Accounts_Status");
    }
}
