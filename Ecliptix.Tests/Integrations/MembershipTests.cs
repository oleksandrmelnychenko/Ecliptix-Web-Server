using System.Data;
using Dapper;

namespace Ecliptix.Tests.Integrations;

internal record LoginMembershipResult
{
    public Guid? MembershipUniqueId { get; init; }
    public string? Status { get; init; }
    public string Outcome { get; init; } = string.Empty;
    
    public byte[] SecureKey { get; init; } = [];
}

[TestClass]
public class MembershipIntegrationTests
{
    private static TestDatabase Db => TestDatabase.Instance;

    [ClassInitialize]
    public static async Task Initialize(TestContext context)
    {
        await Db.InitializeAsync();
    }

    [TestInitialize]
    public async Task TestInitialize()
    {
        await Db.TruncateDatabaseAsync(Db.Connection);
    }
    
    [TestMethod]
    public async Task SignInMembership_ReturnSuccess_WhenValidPhone()
    {
        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumber", "+380501234567");
        
        LoginMembershipResult? result = await Db.Connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );
        
        Console.WriteLine(result!.Outcome);
        
        Assert.IsNotNull(result);
    }
}