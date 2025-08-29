using DbUp;
using DbUp.Engine;
using DbUp.Engine.Output;
using Serilog;
using ILogger = Serilog.ILogger;

namespace Ecliptix.Core.Infrastructure.DbUp;

public static class DbMigrator
{
    public static void ApplyMaster(IConfiguration configuration)
    {
        string basePath = AppContext.BaseDirectory;
        string masterSqlPath = Path.Combine(basePath, configuration.GetValue<string>("DbUp:MasterSqlPath")!);
        
        UpgradeEngine? upgrader = DeployChanges.To
            .SqlDatabase(configuration.GetConnectionString("EcliptixMemberships"))
            .WithScript("Master", File.ReadAllText(masterSqlPath))
            .LogTo(new SerilogUpgradeLog(Log.Logger))
            .Build();

        DatabaseUpgradeResult? result = upgrader.PerformUpgrade();

        if (!result.Successful)
        {
            throw new Exception("Database migration failed. See logs for details.");
        }
    }
}

public class SerilogUpgradeLog(ILogger logger) : IUpgradeLog
{
    public void WriteInformation(string format, params object[] args)
    {
        logger.Information(format, args);
    }

    public void WriteError(string format, params object[] args)
    {
        logger.Error(format, args);
    }

    public void WriteWarning(string format, params object[] args)
    {
        logger.Warning(format, args);
    }
}