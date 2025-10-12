using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema.Configurations;

public class MasterKeyShareConfiguration : EntityBaseMap<MasterKeyShareEntity>
{
    public override void Map(EntityTypeBuilder<MasterKeyShareEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("MasterKeyShares");

        builder.Property(e => e.MembershipUniqueId)
            .IsRequired();

        builder.Property(e => e.ShareIndex)
            .IsRequired();

        builder.Property(e => e.EncryptedShare)
            .HasColumnType("VARBINARY(128)")
            .IsRequired();

        builder.Property(e => e.ShareMetadata)
            .HasColumnType("NVARCHAR(500)")
            .IsRequired();

        builder.Property(e => e.StorageLocation)
            .HasMaxLength(100)
            .IsRequired();

        builder.HasIndex(e => e.ShareIndex)
            .HasDatabaseName("IX_MasterKeyShares_ShareIndex");

        builder.HasIndex(e => new { e.MembershipUniqueId, e.ShareIndex })
            .IsUnique()
            .HasDatabaseName("UQ_MasterKeyShares_MembershipShare");

        builder.HasOne(e => e.Membership)
            .WithMany(m => m.MasterKeyShares)
            .HasForeignKey(e => e.MembershipUniqueId)
            .HasPrincipalKey(m => m.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .HasConstraintName("FK_MasterKeyShares_Memberships");
    }
}