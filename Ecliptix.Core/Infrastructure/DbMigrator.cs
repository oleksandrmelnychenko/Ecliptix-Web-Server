using DbUp;

namespace Ecliptix.Core.Infrastructure;

public class DbMigrator
{
    private readonly string _connectionString;
    private readonly string _sqlFolderPath;

    public DbMigrator(string connectionString, string sqlFolderPath)
    {
        _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
        _sqlFolderPath = sqlFolderPath ?? throw new ArgumentNullException(nameof(sqlFolderPath));
    }

    public void Migrate()
    {
        var upgrader = DeployChanges.To
            .SqlDatabase(_connectionString)
            .WithScriptsFromFileSystem(_sqlFolderPath)
            .LogToConsole()
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
        Console.ResetColor();
    }
}