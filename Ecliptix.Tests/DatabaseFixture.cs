using System.Text.RegularExpressions;
using Dapper;
using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;

namespace Ecliptix.Tests;

public class DatabaseFixture : IAsyncDisposable
{
    private static readonly Regex GoSplitter = new(
        @"^\s*GO\s*(--.*)?$",
        RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled
    );
    
    private readonly MsSqlContainer _container;
    public SqlConnection Connection { get; private set; }

    public DatabaseFixture()
    {
        _container = new MsSqlBuilder()
            .WithPassword("test_password_gDr9r74lhatO")
            .Build();
    }
    
    public async Task InitializeAsync()
    {
        await _container.StartAsync();
        Connection = new SqlConnection(_container.GetConnectionString());
        await Connection.OpenAsync();

        await SetupDatabaseAsync();
    }
    
    public async Task SetupDatabaseAsync()
    {
        await ExecuteSqlFromFileAsync("init.sql");
    }
    
    public async Task TruncateDatabaseAsync()
    {
        await ExecuteSqlFromFileAsync("truncate.sql");
    }
    
    public async Task ExecuteSqlFromFileAsync(string filename)
    {
        string sqlPath = Path.Combine(AppContext.BaseDirectory, "Scripts", filename);

        if (!File.Exists(sqlPath))
        {
            throw new FileNotFoundException($"{filename} not found", sqlPath);
        }

        string sqlScript = await File.ReadAllTextAsync(sqlPath);
        
        string[] batches = GoSplitter.Split(sqlScript);
        foreach (string batch in batches)
        {
            string trimmed = batch.Trim();
            if (!string.IsNullOrEmpty(trimmed))
            {
                try
                {
                    await Connection.ExecuteAsync(trimmed);
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
        await _container.DisposeAsync();
    }
}