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
public class MembershipIntegrationTests : IntegrationTestBase
{
    public MembershipIntegrationTests() : base ("SeedSignInMembership.sql")
    {
    }
    
    [TestMethod]
    public async Task SignInMembership_ReturnPhoneNotFound_WhenInvalidPhone()
    {
        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumber", "+380501234567");
        
        LoginMembershipResult? result = await DbFixture.Connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );
        
        Assert.IsNotNull(result);
        Assert.AreEqual("phone_number_not_found", result.Outcome);
    }
    
    [TestMethod]
    [DataRow("")]
    [DataRow(null)]
    public async Task SignInMembership_ReturnPhoneNumberCannotByEmpty_WhenEmptyPhone(string phone)
    {
        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumber", phone);
        
        LoginMembershipResult? result = await DbFixture.Connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );
        
        Assert.IsNotNull(result);
        Assert.AreEqual("phone_number_cannot_be_empty", result.Outcome);
    }

    [TestMethod]
    public async Task SignInMembership_ReturnMembershipIdNotFound_WhenMembershipIdIsNull()
    {
        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumber", "+380500000001");
        
        LoginMembershipResult? result = await DbFixture.Connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );
        
        Assert.IsNotNull(result);
        Assert.AreEqual("membership_not_found", result.Outcome);
    }
    
    [TestMethod]
    public async Task SignInMembership_ReturnSecureKeyNotSet_WhenSecureKeyIsNull()
    {
        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumber", "+380500000002");
        
        LoginMembershipResult? result = await DbFixture.Connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );
        
        Assert.IsNotNull(result);
        Assert.AreEqual("secure_key_not_set", result.Outcome);
    }
}