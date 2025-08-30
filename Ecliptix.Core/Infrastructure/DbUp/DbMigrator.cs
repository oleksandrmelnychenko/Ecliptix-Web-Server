using DbUp;
using DbUp.Engine;
using DbUp.Helpers;

namespace Ecliptix.Core.Infrastructure.DbUp;

public static class DbMigrator
{ public static void ApplyMaster(IConfiguration configuration)
    
    {
        string basePath = AppContext.BaseDirectory;
        string masterSqlPath = Path.Combine(basePath, configuration.GetValue<string>("DbUp:MasterSqlPath")!);
        
        string[] layers = new[]
        {
            "00_PreDeployment",
            "01_Configuration",
            "02_CoreDomain",
            "03_Relationships",
            "04_CoreBusiness",
            "05_AdvancedFeatures",
            "06_Triggers",
            "07_ViewsHelpers",
            "08_PostDeployment"
        };

        foreach (string layer in layers)
        {
            string path = Path.Combine(masterSqlPath, layer);
            Console.WriteLine($"🚀 Executing layer: {layer}");

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
                Console.WriteLine($"❌ Layer {layer} failed:");
                Console.WriteLine(result.Error);
                Console.ResetColor();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"✅ Layer {layer} executed successfully\n");
            Console.ResetColor();
        }

        Console.WriteLine("🎉 All layers executed successfully!");
        return;
    }
}