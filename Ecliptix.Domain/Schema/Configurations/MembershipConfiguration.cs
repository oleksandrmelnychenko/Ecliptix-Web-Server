using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Domain.Schema.ValueConverters;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ecliptix.Domain.Schema.Configurations;

public class MembershipConfiguration : EntityBaseMap<MembershipEntity>
{
    public override void Map(EntityTypeBuilder<MembershipEntity> builder)
    {
        base.Map(builder);

        builder.ToTable("Memberships");

        builder.Property(e => e.MobileNumberId)
            .IsRequired();

        builder.Property(e => e.AppDeviceId)
            .IsRequired();

        builder.Property(e => e.VerificationFlowId)
            .IsRequired(false);

        builder.Property(e => e.Status)
            .IsRequired()
            .HasMaxLength(20)
            .HasDefaultValue(MembershipStatus.Inactive)
            .HasConversion(new EnumToSnakeCaseConverter<MembershipStatus>());

        builder.Property(e => e.CreationStatus)
            .HasMaxLength(20)
            .HasConversion(new EnumToSnakeCaseConverter<MembershipCreationStatus>());

        builder.ToTable(t => t.HasCheckConstraint("CHK_Memberships_Status",
            "Status IN ('active', 'inactive')"));

        builder.ToTable(t => t.HasCheckConstraint("CHK_Memberships_CreationStatus",
            "CreationStatus IN ('otp_verified', 'secure_key_set', 'passphrase_set')"));

        builder.HasIndex(e => e.UniqueId)
            .IsUnique()
            .HasDatabaseName("UQ_Memberships_UniqueId");

        builder.HasIndex(e => e.MobileNumberId)
            .IsUnique()
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("UQ_Memberships_ActiveMembership");

        builder.HasIndex(e => e.AppDeviceId)
            .HasDatabaseName("IX_Memberships_AppDeviceId");

        builder.HasIndex(e => e.Status)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_Memberships_Status");

        Microsoft.EntityFrameworkCore.SqlServerIndexBuilderExtensions.IncludeProperties(
            builder.HasIndex(e => e.MobileNumberId)
                .HasFilter("IsDeleted = 0 AND Status = 'active'"),
            e => new { e.UniqueId, e.CreationStatus })
            .HasDatabaseName("IX_Memberships_Login_Covering");

        builder.HasOne(e => e.MobileNumber)
            .WithMany(p => p.Memberships)
            .HasForeignKey(e => e.MobileNumberId)
            .HasPrincipalKey(p => p.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .HasConstraintName("FK_Memberships_MobileNumbers");

        builder.HasOne(e => e.AppDevice)
            .WithMany(d => d.Memberships)
            .HasForeignKey(e => e.AppDeviceId)
            .HasPrincipalKey(d => d.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .HasConstraintName("FK_Memberships_Devices");

        builder.HasOne(e => e.VerificationFlow)
            .WithMany(v => v.Memberships)
            .HasForeignKey(e => e.VerificationFlowId)
            .HasPrincipalKey(v => v.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .HasConstraintName("FK_Memberships_VerificationFlows");
    }
}
