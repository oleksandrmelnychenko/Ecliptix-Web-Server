using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema.Configurations;

public class UserConfiguration : EntityBaseMap<UserEntity>
{
    public override void Map(EntityTypeBuilder<UserEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("Users");

        builder.Property(e => e.AccountId)
            .IsRequired();

        builder.Property(e => e.UserName)
            .IsRequired()
            .HasMaxLength(100);

        builder.Property(e => e.DisplayName)
            .IsRequired()
            .HasMaxLength(200);

        builder.HasIndex(e => e.AccountId)
            .IsUnique()
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("UQ_Users_AccountId_Active");

        builder.HasIndex(e => e.UserName)
            .IsUnique()
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("UQ_Users_UserName_Active");

        builder.HasOne(e => e.Account)
            .WithOne(a => a.User)
            .HasForeignKey<UserEntity>(e => e.AccountId)
            .HasPrincipalKey<AccountEntity>(a => a.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .IsRequired()
            .HasConstraintName("FK_Users_Accounts");
    }
}
