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
        string masterSqlPath = configuration.GetValue<string>("DbUp:MasterSqlPath")!;
        string expandedSql = ExpandSqlIncludeFiles(masterSqlPath);

        UpgradeEngine upgrader = DeployChanges.To
            .SqlDatabase(configuration.GetConnectionString("EcliptixMemberships"))
            .WithScript("Master", expandedSql)
            .LogTo(new SerilogUpgradeLog(Log.Logger))
            .Build();

        DatabaseUpgradeResult result = upgrader.PerformUpgrade();

        if (!result.Successful)
        {
            throw new Exception("Database migration failed. See logs for details.");
        }
    }

    private static string ExpandSqlIncludeFiles(string masterSqlPath)
    {
        string masterDirectory = Path.GetDirectoryName(masterSqlPath)!;
        string masterContent = File.ReadAllText(masterSqlPath);
        
        // Replace all :r commands with actual file content
        string result = System.Text.RegularExpressions.Regex.Replace(
            masterContent, 
            @"^\s*:r\s+(.+)\s*$",
            match => {
                string relativePath = match.Groups[1].Value.Trim();
                string fullPath = Path.Combine(masterDirectory, relativePath);
                
                if (!File.Exists(fullPath))
                {
                    throw new FileNotFoundException($"SQL include file not found: {fullPath}");
                }
                
                string includeContent = File.ReadAllText(fullPath);
                
                // Add a comment indicating the source file
                return $"-- BEGIN: {relativePath}\n{includeContent}\n-- END: {relativePath}";
            },
            System.Text.RegularExpressions.RegexOptions.Multiline
        );
        
        return result;
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