using System.Data;
using System.Text.RegularExpressions;
using Akka.TestKit.Xunit2;
using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;
using Dapper;
using Ecliptix.Domain.Memberships.ActorEvents;

namespace Ecliptix.Tests.Integrations;

internal record LoginMembershipResult
{
    public Guid? MembershipUniqueId { get; init; }
    public string? Status { get; init; }
    public string Outcome { get; init; } = string.Empty;
    
    public byte[] SecureKey { get; init; } = [];
}

[TestClass]
public class MembershipIntegrationTests : TestKit
{
    private static MsSqlContainer _sqlContainer;
    private static SqlConnection _connection;

    [ClassInitialize]
    public static async Task Initialize(TestContext context)
    {
        _sqlContainer = new MsSqlBuilder()
            .WithPassword("test_password_gDr9r74lhatO")
            .Build();
        
        await _sqlContainer.StartAsync();
        
        _connection = new SqlConnection(_sqlContainer.GetConnectionString());
        await _connection.OpenAsync();

        await SetupDatabaseAsync(_connection);
    }

    [TestMethod]
    public async Task SignInMembership_ReturnSuccess_WhenValidPhone()
    {
        SignInMembershipActorEvent cmd = new(
            PhoneNumber: "+380501234567",
            OpaqueSignInInitRequest: null!,
            CultureName: string.Empty);
        
        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumber", cmd.PhoneNumber);

        
        LoginMembershipResult? result = await _connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );
        

        Console.WriteLine(result!.Outcome);
        
        Assert.IsNotNull(result);
    }

    private static async Task SetupDatabaseAsync(SqlConnection connection)
    {
        var sqlPath = Path.Combine(AppContext.BaseDirectory, "Scripts", "init.sql");

        if (!File.Exists(sqlPath))
            throw new FileNotFoundException("init.sql not found", sqlPath);

        var sqlScript = await File.ReadAllTextAsync(sqlPath);

        string[] batches = Regex.Split(sqlScript, @"^\s*GO\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase);
        
        foreach (var batch in batches)
        {
            var trimmed = batch.Trim();
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
}