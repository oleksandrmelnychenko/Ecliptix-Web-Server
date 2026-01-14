using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.IdentityAccess.Domain.Schema.Configurations;

public class MasterKeyShareConfiguration : EntityBaseMap<MasterKeyShareEntity>
{
    public override void Map(EntityTypeBuilder<MasterKeyShareEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("master_key_shares");

        builder.Property(e => e.AccountId)
            .IsRequired();

        builder.Property(e => e.ShareIndex)
            .IsRequired();

        builder.Property(e => e.EncryptedShare)
            .IsRequired()
            .HasColumnType("bytea");

        builder.Property(e => e.ShareMetadata)
            .IsRequired()
            .HasColumnType("varchar(500)");

        builder.Property(e => e.StorageLocation)
            .IsRequired()
            .HasMaxLength(100);

        builder.Property(e => e.CredentialsVersion)
            .HasDefaultValue(1);

        builder.HasIndex(e => new { e.AccountId, e.ShareIndex })
            .IsUnique()
            .HasDatabaseName("UQ_MasterKeyShares_AccountShare");

        builder.HasIndex(e => e.ShareIndex)
            .HasDatabaseName("IX_MasterKeyShares_ShareIndex");

        builder.HasOne(e => e.Account)
            .WithMany(a => a.MasterKeyShares)
            .HasForeignKey(e => e.AccountId)
            .HasPrincipalKey(a => a.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .HasConstraintName("FK_MasterKeyShares_Accounts");
    }
}
