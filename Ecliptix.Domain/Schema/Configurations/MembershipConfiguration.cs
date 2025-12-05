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
            "status IN ('active', 'inactive')"));

        builder.ToTable(t => t.HasCheckConstraint("CHK_Memberships_CreationStatus",
            "creation_status IN ('otp_verified', 'secure_key_set', 'passphrase_set')"));

        builder.HasIndex(e => e.UniqueId)
            .IsUnique()
            .HasDatabaseName("UQ_Memberships_UniqueId");

        builder.HasIndex(e => e.MobileNumberId)
            .IsUnique()
            .HasFilter("is_deleted = false")
            .HasDatabaseName("UQ_Memberships_ActiveMembership");

        builder.HasIndex(e => e.AppDeviceId)
            .HasDatabaseName("IX_Memberships_AppDeviceId");

        builder.HasIndex(e => e.Status)
            .HasFilter("is_deleted = false")
            .HasDatabaseName("IX_Memberships_Status");

        builder.HasOne(e => e.MobileNumber)
            .WithMany(p => p.Memberships)
            .HasForeignKey(e => e.MobileNumberId)
            .HasPrincipalKey(p => p.UniqueId)
            .OnDelete(DeleteBehavior.NoAction)
            .HasConstraintName("FK_Memberships_MobileNumbers");

        builder.HasOne(e => e.AppDevice)
            .WithMany(d => d.Memberships)
            .HasForeignKey(e => e.AppDeviceId)
            .HasPrincipalKey(d => d.DeviceId)
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
