using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Schema.Configurations;

public class MembershipConfiguration : EntityBaseMap<MembershipEntity>
{
    public override void Map(EntityTypeBuilder<MembershipEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("Memberships");

        builder.HasMany(e => e.Accounts)
            .WithOne(a => a.Membership)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_Accounts_Memberships");
        
        builder.HasMany(e => e.MasterKeyShares)
            .WithOne(e => e.Membership)
            .HasForeignKey(e => e.MembershipUniqueId)
            .HasPrincipalKey(m => m.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_Master KeyShares_Memberships");
    }
}