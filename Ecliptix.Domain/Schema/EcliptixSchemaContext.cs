using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Domain.Schema.Configurations;

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
    public DbSet<MobileDeviceEntity> MobileDevices { get; set; }
    public DbSet<LogoutAuditEntity> LogoutAudits { get; set; }

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
        modelBuilder.AddConfiguration(new LoginAttemptConfiguration());
        modelBuilder.AddConfiguration(new MobileDeviceConfiguration());
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
}