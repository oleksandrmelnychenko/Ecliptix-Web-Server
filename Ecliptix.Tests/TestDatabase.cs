using System.Text.RegularExpressions;
using Dapper;
using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;

namespace Ecliptix.Tests;

public class TestDatabase : IAsyncDisposable
{
    private static TestDatabase _instance;
    public static TestDatabase Instance => _instance ??= new TestDatabase();
    
    public MsSqlContainer SqlContainer { get; private set; }
    public SqlConnection Connection { get; private set; }
    
    private bool _initialized;
    
    private TestDatabase() { }
    
    public async Task InitializeAsync()
    {
        if (_initialized) return;

        SqlContainer = new MsSqlBuilder()
            .WithPassword("test_password_gDr9r74lhatO")
            .Build();

        await SqlContainer.StartAsync();
        
        Connection = new SqlConnection(SqlContainer.GetConnectionString());
        await Connection.OpenAsync();

        await SetupDatabaseAsync(Connection);
        
        _initialized = true;
    }
    
    public async Task SetupDatabaseAsync(SqlConnection connection)
    {
        if (_initialized) return;

        await ExecuteSqlFromFileAsync(connection, "init.sql");
        
        _initialized = true;
    }
    
    public async Task TruncateDatabaseAsync(SqlConnection connection)
    {
        if (!_initialized) return;
        
        await ExecuteSqlFromFileAsync(connection, "truncate.sql");
        
        _initialized = false;
    }
    
    private static async Task ExecuteSqlFromFileAsync(SqlConnection connection, string filename)
    {
        string sqlPath = Path.Combine(AppContext.BaseDirectory, "Scripts", filename);

        if (!File.Exists(sqlPath))
        {
            throw new FileNotFoundException($"{filename} not found", sqlPath);
        }

        string sqlScript = await File.ReadAllTextAsync(sqlPath);
        
        string[] batches = Regex.Split(sqlScript, @"^\s*GO\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase);

        foreach (string batch in batches)
        {
            string trimmed = batch.Trim();
            if (!string.IsNullOrEmpty(trimmed))
            {
                try
                {
                    await connection.ExecuteAsync(trimmed);
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to execute SQL batch:\n{trimmed}", ex);
                }
            }
        }
    }
    
    public async ValueTask DisposeAsync()
    {
        await Connection.DisposeAsync();
        await SqlContainer.DisposeAsync();
    }
}