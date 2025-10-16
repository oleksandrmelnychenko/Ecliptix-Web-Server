using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Ecliptix.Domain.Schema;

public class EcliptixSchemaContextFactory : IDesignTimeDbContextFactory<EcliptixSchemaContext>
{
    public EcliptixSchemaContext CreateDbContext(string[] args)
    {
        DbContextOptionsBuilder<EcliptixSchemaContext> optionsBuilder = new();

        string connectionString = "Data Source=78.152.175.67;Initial Catalog=EcliptixMemberships;Integrated Security=False;User ID=ef_migrator;Password=Grimm_jow92;Connect Timeout=30;Encrypt=False;TrustServerCertificate=True;ApplicationIntent=ReadWrite;MultiSubnetFailover=False;";

        optionsBuilder.UseSqlServer(connectionString);

        return new EcliptixSchemaContext(optionsBuilder.Options);
    }
}
