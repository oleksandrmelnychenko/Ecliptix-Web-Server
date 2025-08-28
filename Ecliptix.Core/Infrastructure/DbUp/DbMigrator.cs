using DbUp;

namespace Ecliptix.Core.Infrastructure.DbUp;

public class DbMigrator
{
    private readonly string _connectionString;
    private readonly string _sqlFolderPath;

    private DbMigrator(string connectionString, string? sqlFolderPath = null)
    {
        _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
        _sqlFolderPath = sqlFolderPath ?? throw new ArgumentNullException(nameof(sqlFolderPath));

        if (!Directory.Exists(_sqlFolderPath))
        {
            Directory.CreateDirectory(_sqlFolderPath);
        }
    }

    public static void Use(string[]? args = null)
    {
        try
        {
            args ??= [];

            if (args.Length == 0)
            {
                DisplayHelp();
                return;
            }

            // Load configuration from appsettings.json
            IConfiguration configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true)
                .AddEnvironmentVariables()
                .Build();

            // Try environment variables first, then fall back to appsettings.json
            string connectionString = Environment.GetEnvironmentVariable("ECLIPTIX_DB_CONNECTION") 
                ?? configuration["ConnectionStrings:EcliptixMemberships"]
                ?? throw new InvalidOperationException("Database connection string not found. Set it in environment variable ECLIPTIX_DB_CONNECTION or in appsettings.json at Database:ConnectionString");

            string sqlFolder = Environment.GetEnvironmentVariable("ECLIPTIX_MIGRATIONS_PATH")
                               ?? configuration["Migration:MasterSqlFolder"]!;
                
            var migrator = new DbMigrator(connectionString, sqlFolder);

            switch (args[0].ToLower())
            {
                case "migrate":
                    migrator.Migrate();
                    break;
                case "list":
                    migrator.ListAppliedScripts();
                    break;
                case "create":
                    if (args.Length < 2)
                    {
                        Console.WriteLine("Usage: create <migration_name>");
                        return;
                    }
                    migrator.CreateMigrationScript(args[1]);
                    break;
                case "info":
                    migrator.DisplayMigrationInfo();
                    break;
                default:
                    DisplayHelp();
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error: {ex.Message}");
            Console.ResetColor();
            Environment.ExitCode = 1;
        }
    }

    private static void DisplayHelp()
    {
        Console.WriteLine("Ecliptix Database Migration Tool");
        Console.WriteLine("================================");
        Console.WriteLine("Commands:");
        Console.WriteLine("  migrate       - Run all pending migrations");
        Console.WriteLine("  list          - List all applied migrations");
        Console.WriteLine("  create <name> - Create a new migration script");
        Console.WriteLine("  info          - Display migration status information");
        Console.WriteLine();
        Console.WriteLine("Environment variables:");
        Console.WriteLine("  ECLIPTIX_DB_CONNECTION  - Database connection string");
        Console.WriteLine("  ECLIPTIX_MIGRATIONS_PATH - Path to SQL migration scripts (optional)");
    }

    private void Migrate()
    {
        Console.WriteLine($"Starting database migration from {_sqlFolderPath}");
        
        var upgrader = DeployChanges.To
            .SqlDatabase(_connectionString)
            .WithScriptsFromFileSystem(_sqlFolderPath)
            .LogToConsole()
            .WithTransaction()
            .WithExecutionTimeout(TimeSpan.FromMinutes(5))
            .Build();

        var result = upgrader.PerformUpgrade();

        if (!result.Successful)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(result.Error);
            Console.ResetColor();
            throw new Exception("Database migration failed. See the error message above for details.");
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("Database migration successful!");
        if (result.Scripts.Any())
        {
            Console.WriteLine($"Applied {result.Scripts.Count()} migration scripts:");
            foreach (var script in result.Scripts)
            {
                Console.WriteLine($"  - {script.Name}");
            }
        }
        else
        {
            Console.WriteLine("Database is already up to date.");
        }
        Console.ResetColor();
    }

    private void ListAppliedScripts()
    {
        var upgradeEngine = DeployChanges.To
            .SqlDatabase(_connectionString)
            .WithScriptsFromFileSystem(_sqlFolderPath)
            .LogToConsole()
            .Build();

        var executedScripts = upgradeEngine.GetExecutedScripts();
        
        Console.WriteLine("Applied migrations:");
        if (executedScripts.Any())
        {
            foreach (var script in executedScripts)
            {
                Console.WriteLine($"  - {script}");
            }
            Console.WriteLine($"Total: {executedScripts.Count()} scripts applied");
        }
        else
        {
            Console.WriteLine("  No migrations have been applied yet.");
        }
    }

    private void CreateMigrationScript(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Migration name cannot be empty", nameof(name));
        }
        
        // Sanitize the filename
        string safeName = string.Join("_", name.Split(Path.GetInvalidFileNameChars()));
        string timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
        string filename = $"{timestamp}_{safeName}.sql";
        string fullPath = Path.Combine(_sqlFolderPath, filename);
        
        string template = $"-- Migration: {name}\n-- Created: {DateTime.Now}\n\n-- Write your SQL statements here\n\n";
        File.WriteAllText(fullPath, template);
        
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"Created migration script: {filename}");
        Console.WriteLine($"Location: {fullPath}");
        Console.ResetColor();
    }

    private void DisplayMigrationInfo()
    {
        var upgradeEngine = DeployChanges.To
            .SqlDatabase(_connectionString)
            .WithScriptsFromFileSystem(_sqlFolderPath)
            .LogToConsole()
            .Build();

        var executedScripts = upgradeEngine.GetExecutedScripts().ToList();
        var allScripts = upgradeEngine.GetDiscoveredScripts().ToList();
        var pendingScripts = allScripts.Where(s => !executedScripts.Contains(s.Name)).ToList();
        
        Console.WriteLine("Database Migration Status");
        Console.WriteLine("========================");
        Console.WriteLine($"Connection: {MaskConnectionString(_connectionString)}");
        Console.WriteLine($"Scripts folder: {_sqlFolderPath}");
        Console.WriteLine($"Total scripts: {allScripts.Count}");
        Console.WriteLine($"Applied scripts: {executedScripts.Count}");
        Console.WriteLine($"Pending scripts: {pendingScripts.Count}");
        
        if (pendingScripts.Any())
        {
            Console.WriteLine("\nPending migrations:");
            foreach (var script in pendingScripts)
            {
                Console.WriteLine($"  - {script.Name}");
            }
        }
    }

    private string MaskConnectionString(string connectionString)
    {
        // Basic masking for security in logs
        if (string.IsNullOrEmpty(connectionString)) return "[empty]";
        
        var parts = connectionString.Split(';')
            .Select(part => {
                if (part.StartsWith("Password=", StringComparison.OrdinalIgnoreCase) ||
                    part.StartsWith("Pwd=", StringComparison.OrdinalIgnoreCase))
                {
                    return part.Split('=')[0] + "=*****";
                }
                return part;
            });
        
        return string.Join(";", parts);
    }
}
