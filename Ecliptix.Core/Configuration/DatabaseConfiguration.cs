namespace Ecliptix.Core.Configuration;

public sealed class DatabaseConfiguration
{
    public const string SectionName = "Database";

    public string ConnectionString { get; set; } = string.Empty;

    public string MigrationsAssembly { get; set; } = "Ecliptix.IdentityAccess.Infrastructure";

    public string Schema { get; set; } = "public";
}
