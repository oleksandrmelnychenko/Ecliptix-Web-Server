using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Schema.Configurations;

public class MembershipAttemptConfiguration : EntityBaseMap<MembershipAttempt>
{
    public override void Map(EntityTypeBuilder<MembershipAttempt> builder)
    {
        base.Map(builder);

        builder.ToTable("MembershipAttempts");

        builder.Property(e => e.MembershipId)
            .IsRequired();

        builder.Property(e => e.AttemptType)
            .IsRequired()
            .HasMaxLength(50);

        builder.Property(e => e.Status)
            .IsRequired()
            .HasMaxLength(20);

        builder.Property(e => e.ErrorMessage)
            .HasMaxLength(500);

        builder.Property(e => e.AttemptedAt)
            .HasDefaultValueSql("GETUTCDATE()");

        builder.HasIndex(e => new { e.MembershipId, e.AttemptedAt })
            .IsDescending(false, true)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_MembershipAttempts_Membership_AttemptedAt");

        builder.HasIndex(e => e.Status)
            .HasFilter("IsDeleted = 0")
            .HasDatabaseName("IX_MembershipAttempts_Status");

        builder.HasOne(e => e.Membership)
            .WithMany(m => m.MembershipAttempts)
            .HasForeignKey(e => e.MembershipId)
            .HasPrincipalKey(m => m.UniqueId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_MembershipAttempts_Memberships");
    }
}