using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Domain.Schema.Configurations;
using Ecliptix.Domain.Schema.Interfaces;

namespace Ecliptix.Domain.Schema;

public class EcliptixSchemaContext : DbContext
{
    public EcliptixSchemaContext(DbContextOptions<EcliptixSchemaContext> options) : base(options)
    {
    }

    public DbSet<MobileNumberEntity> MobileNumbers { get; set; }
    public DbSet<DeviceEntity> Devices { get; set; }
    public DbSet<VerificationFlowEntity> VerificationFlows { get; set; }
    public DbSet<OtpCodeEntity> OtpCodes { get; set; }
    public DbSet<FailedOtpAttemptEntity> FailedOtpAttempts { get; set; }
    public DbSet<MembershipEntity> Memberships { get; set; }
    public DbSet<MasterKeyShareEntity> MasterKeyShares { get; set; }
    public DbSet<LoginAttemptEntity> LoginAttempts { get; set; }
    public DbSet<LogoutAuditEntity> LogoutAudits { get; set; }
    public DbSet<AccountEntity> Accounts { get; set; }
    public DbSet<DeviceContextEntity> DeviceContexts { get; set; }
    public DbSet<AccountSecureKeyAuthEntity> AccountSecureKeyAuths { get; set; }
    public DbSet<AccountPinAuthEntity> AccountPinAuths { get; set; }
    public DbSet<VerificationLogEntity> VerificationLogs { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.AddConfiguration(new MobileNumberConfiguration());
        modelBuilder.AddConfiguration(new DeviceConfiguration());
        modelBuilder.AddConfiguration(new VerificationFlowConfiguration());
        modelBuilder.AddConfiguration(new OtpCodeConfiguration());
        modelBuilder.AddConfiguration(new FailedOtpAttemptConfiguration());
        modelBuilder.AddConfiguration(new MasterKeyShareConfiguration());
        modelBuilder.AddConfiguration(new MembershipConfiguration());
        modelBuilder.AddConfiguration(new AccountConfiguration());
        modelBuilder.AddConfiguration(new DeviceContextConfiguration());
        modelBuilder.AddConfiguration(new LoginAttemptConfiguration());
        modelBuilder.AddConfiguration(new LogoutAuditConfiguration());
        modelBuilder.AddConfiguration(new AccountSecureKeyAuthConfiguration());
        modelBuilder.AddConfiguration(new AccountPinAuthConfiguration());
        modelBuilder.AddConfiguration(new VerificationLogConfiguration());
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            throw new InvalidOperationException(
                "DbContext is not configured. Ensure connection string is provided through dependency injection or design-time factory.");
        }
    }

    public override int SaveChanges()
    {
        ApplyAuditInformation();
        return base.SaveChanges();
    }

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        ApplyAuditInformation();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        ApplyAuditInformation();
        return base.SaveChangesAsync(cancellationToken);
    }

    public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        ApplyAuditInformation();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    private void ApplyAuditInformation()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        IEnumerable<EntityEntry<EntityBase>> entries = ChangeTracker.Entries<EntityBase>();

        foreach (EntityEntry<EntityBase> entry in entries)
        {
            if (entry.Entity is not IAuditable auditable)
            {
                continue;
            }

            switch (entry.State)
            {
                case EntityState.Added:
                    auditable.CreatedAt = now;
                    auditable.UpdatedAt = now;
                    auditable.IsDeleted = false;
                    break;

                case EntityState.Modified:
                    auditable.UpdatedAt = now;
                    break;

                case EntityState.Deleted:
                    entry.State = EntityState.Modified;
                    auditable.IsDeleted = true;
                    auditable.UpdatedAt = now;
                    break;
            }
        }
    }
}
