using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace Ecliptix.Domain.Schema;

public class EcliptixSchemaContextFactory : IDesignTimeDbContextFactory<EcliptixSchemaContext>
{
    public EcliptixSchemaContext CreateDbContext(string[] args)
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false)
            .AddEnvironmentVariables()
            .Build();

        DbContextOptionsBuilder<EcliptixSchemaContext> optionsBuilder = new DbContextOptionsBuilder<EcliptixSchemaContext>();

        string? connectionString = configuration.GetConnectionString("EcliptixMemberships")
            ?? throw new InvalidOperationException("Connection string 'EcliptixMemberships' not found in appsettings.json");

        optionsBuilder.UseSqlServer(connectionString);

        return new EcliptixSchemaContext(optionsBuilder.Options);
    }
}