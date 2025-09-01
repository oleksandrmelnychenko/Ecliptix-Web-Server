using DbUp;
using DbUp.Engine;
using DbUp.Helpers;

namespace Ecliptix.Core.Infrastructure.DbUp;

public static class DbMigrator
{ 
    public static void ApplyMaster(IConfiguration configuration)
    {
        string basePath = AppContext.BaseDirectory;

        string path = Path.Combine(basePath, "PersistorScripts", "old_scripts");

        var upgrader = DeployChanges.To
            .SqlDatabase(configuration.GetConnectionString("EcliptixMemberships")!)
            .WithScriptsFromFileSystem(path)
            .JournalTo(new NullJournal())
            .LogToConsole()
            .Build();

        DatabaseUpgradeResult? result = upgrader.PerformUpgrade();

        if (!result.Successful)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(result.Error);
            Console.ResetColor();
            return;
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.ResetColor();
            
        Console.WriteLine("🎉 All layers executed successfully!");
    }
}