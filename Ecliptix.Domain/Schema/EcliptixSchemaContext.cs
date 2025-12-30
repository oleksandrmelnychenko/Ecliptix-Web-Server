using Ecliptix.Domain.Schema.Configurations;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Domain.Schema.Interceptors;
using Microsoft.EntityFrameworkCore;

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
    public DbSet<AccountProfileEntity> AccountProfiles { get; set; }
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
        modelBuilder.AddConfiguration(new AccountProfileConfiguration());
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
}
