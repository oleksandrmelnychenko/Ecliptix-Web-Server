using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Domain.Schema.Configurations;
using Ecliptix.Domain.Schema.Interfaces;

namespace Ecliptix.Domain.Schema;

public class EcliptixSchemaContext : DbContext
{
    private Guid? _currentActorId;

    public EcliptixSchemaContext(DbContextOptions<EcliptixSchemaContext> options) : base(options)
    {
    }

    public void SetCurrentActor(Guid? actorId)
    {
        _currentActorId = actorId;
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
                    auditable.CreatedBy = _currentActorId;
                    auditable.UpdatedAt = now;
                    auditable.UpdatedBy = _currentActorId;
                    auditable.IsDeleted = false;
                    auditable.DeletedAt = null;
                    auditable.DeletedBy = null;
                    break;

                case EntityState.Modified:
                    auditable.UpdatedAt = now;
                    auditable.UpdatedBy = _currentActorId;
                    break;

                case EntityState.Deleted:
                    entry.State = EntityState.Modified;
                    auditable.IsDeleted = true;
                    auditable.DeletedAt = now;
                    auditable.DeletedBy = _currentActorId;
                    auditable.UpdatedAt = now;
                    auditable.UpdatedBy = _currentActorId;
                    break;
            }
        }
    }
}
