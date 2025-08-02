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
public class LoginMembershipProcedureTests : IntegrationTestBase
{
    [TestMethod]
    public async Task LoginMembership_ReturnPhoneNotFound_WhenInvalidPhone()
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
    //[DataRow(null)] неможливо виконати команду з null, IF @PhoneNumber IS NULL OR @PhoneNumber = '' | IS NULL не спрацює
    public async Task LoginMembership_ReturnPhoneNumberCannotByEmpty_WhenEmptyPhone(string phone)
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
    public async Task LoginMembership_ReturnMembershipIdNotFound_WhenMembershipIdIsNull()
    {
        // Assert

        await DataSeeder.Build(DbFixture.Connection)
            .WithPhone("+380500000000", 10)
            .SeedAsync();

        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumber", "+380500000000");
        
        // Act
        
        LoginMembershipResult? result = await DbFixture.Connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );
        
        // Assert
        
        Assert.IsNotNull(result);
        Assert.AreEqual("membership_not_found", result.Outcome);
    }
    
    [TestMethod]
    public async Task LoginMembership_ReturnSecureKeyNotSet_WhenSecureKeyIsNull()
    {
        // Arrange
        await DataSeeder.Build(DbFixture.Connection)
            .WithPhone("+380500000000")
            .WithAppDevice()
            .WithVerificationFlow()
            .WithMembership()
            .SeedAsync();
        
        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumber", "+380500000000");
        
        // Act
        
        LoginMembershipResult? result = await DbFixture.Connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );
        
        // Assert
        
        Assert.IsNotNull(result);
        Assert.AreEqual("secure_key_not_set", result.Outcome);
    }
    
}