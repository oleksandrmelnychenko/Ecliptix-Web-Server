using DbUp;
using DbUp.Engine;
using DbUp.Helpers;
using Serilog;

namespace Ecliptix.Core.Infrastructure.DbUp;

public static class DbMigrator
{
    public static void ApplySql(IConfiguration configuration)
    {
        try
        {
            Log.Information("[DbUp] Starting DB migration for {Database}",
                configuration.GetConnectionString("EcliptixMemberships")?.Split(';')[0]);

            string basePath = AppContext.BaseDirectory;
            string path = Path.Combine(basePath, "PersistorScripts", "old_scripts");

            if (!Directory.Exists(path))
            {
                Log.Warning("[DbUp] Script folder not found: {Path}", path);
                Log.Fatal("[DbUp] Migration scripts directory not found. Application cannot start.");
                Environment.Exit(1);
            }

            var upgrader = DeployChanges.To
                .SqlDatabase(configuration.GetConnectionString("EcliptixMemberships")!)
                .WithScriptsFromFileSystem(path)
                .JournalTo(new NullJournal())
                .Build();

            DatabaseUpgradeResult result = upgrader.PerformUpgrade();

            if (!result.Successful)
            {
                Log.Fatal(result.Error, "[DbUp] Database migration failed. Application cannot start.");
                Environment.Exit(1);
            }
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "[DbUp] Unexpected error during database migration. Application cannot start.");
            Environment.Exit(1);
        }
    }
}