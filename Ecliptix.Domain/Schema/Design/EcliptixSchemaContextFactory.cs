using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Ecliptix.Domain.Schema.Design;

public class EcliptixSchemaContextFactory : IDesignTimeDbContextFactory<EcliptixSchemaContext>
{
    public EcliptixSchemaContext CreateDbContext(string[] args)
    {
        DbContextOptionsBuilder<EcliptixSchemaContext> optionsBuilder = new();

        optionsBuilder.UseNpgsql(
            "Host=localhost;Port=5433;Database=ecliptix_memberships;Username=ecliptix_admin;Password=Dev_Password_2024",
            npgsqlOptions =>
            {
                npgsqlOptions.CommandTimeout(30);
            })
            .UseSnakeCaseNamingConvention();

        return new EcliptixSchemaContext(optionsBuilder.Options);
    }
}
