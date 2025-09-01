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
        string configuredPath = configuration.GetValue<string>("DbUp:MasterSqlPath")!;
        string masterSqlPath = ResolveMasterSqlPath(configuredPath);
        string expandedSql = ExpandSqlIncludeFiles(masterSqlPath);

        string sqlConnectionString = configuration.GetConnectionString("EcliptixMemberships")!;
        
        UpgradeEngine upgrader = DeployChanges.To
            .SqlDatabase(sqlConnectionString)
            .WithScript("Master", expandedSql)
            .LogTo(new SerilogUpgradeLog(Log.Logger))
            .Build();

        DatabaseUpgradeResult result = upgrader.PerformUpgrade();

        if (!result.Successful)
        {
            throw new Exception("Database migration failed. See logs for details.");
        }
    }

    private static string ResolveMasterSqlPath(string configuredPath)
    {
        if (Path.IsPathRooted(configuredPath) && File.Exists(configuredPath))
        {
            return configuredPath;
        }

        string baseDirectoryPath = Path.Combine(AppContext.BaseDirectory, configuredPath);
        if (File.Exists(baseDirectoryPath))
        {
            return baseDirectoryPath;
        }

        string sourceDirectoryPath = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Ecliptix.Domain",
            "PersistorScripts", "MasterDeployment.sql");
        sourceDirectoryPath = Path.GetFullPath(sourceDirectoryPath);
        if (File.Exists(sourceDirectoryPath))
        {
            return sourceDirectoryPath;
        }

        throw new FileNotFoundException($"Could not find MasterDeployment.sql. Searched paths:\n" +
                                        $"1. {configuredPath} (configured path)\n" +
                                        $"2. {baseDirectoryPath} (AppContext.BaseDirectory + configured path)\n" +
                                        $"3. {sourceDirectoryPath} (source directory fallback)");
    }

    private static string ExpandSqlIncludeFiles(string masterSqlPath)
    {
        string masterDirectory = Path.GetDirectoryName(masterSqlPath)!;
        string masterContent = File.ReadAllText(masterSqlPath);

        string result = System.Text.RegularExpressions.Regex.Replace(
            masterContent,
            @"^\s*:r\s+(.+)\s*$",
            match =>
            {
                string relativePath = match.Groups[1].Value.Trim();
                string fullPath = Path.Combine(masterDirectory, relativePath);

                if (!File.Exists(fullPath))
                {
                    throw new FileNotFoundException($"SQL include file not found: {fullPath}");
                }

                string includeContent = File.ReadAllText(fullPath);

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