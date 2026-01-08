using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Ecliptix.IdentityAccess.Domain.Schema.Design;

public class EcliptixSchemaContextFactory : IDesignTimeDbContextFactory<EcliptixSchemaContext>
{
    public EcliptixSchemaContext CreateDbContext(string[] args)
    {
        DbContextOptionsBuilder<EcliptixSchemaContext> optionsBuilder = new();

        string? connectionString = ResolveConnectionString();
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "Database connection string is not configured. Set Database__ConnectionString or ConnectionStrings__EcliptixMemberships.");
        }

        optionsBuilder.UseNpgsql(connectionString, npgsqlOptions =>
        {
            npgsqlOptions.CommandTimeout(30);
            npgsqlOptions.MigrationsAssembly("Ecliptix.IdentityAccess.Infrastructure");
        })
        .UseSnakeCaseNamingConvention()
        .ConfigureWarnings(warnings =>
            warnings.Ignore(RelationalEventId.PendingModelChangesWarning));

        return new EcliptixSchemaContext(optionsBuilder.Options);
    }

    private static string? ResolveConnectionString()
    {
        string? connectionString = Environment.GetEnvironmentVariable("Database__ConnectionString");
        if (!string.IsNullOrWhiteSpace(connectionString))
        {
            return connectionString;
        }

        connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__EcliptixMemberships");
        if (!string.IsNullOrWhiteSpace(connectionString))
        {
            return connectionString;
        }

        foreach (string candidate in GetCandidateSettingsFiles())
        {
            string? fromFile = TryReadConnectionString(candidate);
            if (!string.IsNullOrWhiteSpace(fromFile))
            {
                return fromFile;
            }
        }

        return null;
    }

    private static IEnumerable<string> GetCandidateSettingsFiles()
    {
        string root = Directory.GetCurrentDirectory();
        yield return Path.Combine(root, "Ecliptix.Core", "appsettings.Development.Local.json");
        yield return Path.Combine(root, "Ecliptix.Core", "appsettings.Development.json");
        yield return Path.Combine(root, "Ecliptix.Core", "appsettings.json");
    }

    private static string? TryReadConnectionString(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(path));
            JsonElement root = document.RootElement;

            if (root.TryGetProperty("Database", out JsonElement database) &&
                database.TryGetProperty("ConnectionString", out JsonElement databaseConnection))
            {
                return databaseConnection.GetString();
            }

            if (root.TryGetProperty("ConnectionStrings", out JsonElement connectionStrings) &&
                connectionStrings.TryGetProperty("EcliptixMemberships", out JsonElement namedConnection))
            {
                return namedConnection.GetString();
            }
        }
        catch (JsonException)
        {
        }
        catch (IOException)
        {
        }

        return null;
    }
}
