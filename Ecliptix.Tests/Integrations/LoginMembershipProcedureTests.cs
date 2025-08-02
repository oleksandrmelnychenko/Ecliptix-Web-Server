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
    public async Task SignInMembership_ReturnLockoutTime_WhenAccountIsLockedOut()
    {
        // Arrange
        string phoneNumber = "+380501234567";
        DateTime lockoutUntil = DateTime.UtcNow.AddMinutes(30);
        string lockoutOutcome = $"LOCKED_UNTIL:{lockoutUntil:yyyy-MM-ddTHH:mm:ss.fffffffZ}";

        await DataSeeder.Build(DbFixture.Connection)
            .WithLoginAttempt(phoneNumber, lockoutOutcome, isSuccess: false)
            .SeedAsync();

        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumber", "+380501234567");

        // Act
        LoginMembershipResult? result = await DbFixture.Connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        // Assert
        Assert.IsNotNull(result);
        Assert.IsNull(result.MembershipUniqueId);
        Assert.IsNull(result.Status);
        Assert.AreEqual(result.SecureKey, []);
        Assert.IsNotNull(result.Outcome);
    
        // Should return remaining lockout time in minutes
        int remainingMinutes = int.Parse(result.Outcome);
        Assert.IsTrue(remainingMinutes > 0 && remainingMinutes <= 30);
    }
    
    [TestMethod]
    public async Task LoginMembership_ReturnPhoneNotFound_WhenInvalidPhone()
    {
        // Arrange
        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumber", "+380501234567");
        
        // Act
        LoginMembershipResult? result = await DbFixture.Connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );
        
        // Assert
        Assert.IsNotNull(result);
        Assert.AreEqual("phone_number_not_found", result.Outcome);
    }
    
    [TestMethod]
    [DataRow("")]
    //[DataRow(null)] неможливо виконати команду з null, IF @PhoneNumber IS NULL OR @PhoneNumber = '' | IS NULL не спрацює
    public async Task LoginMembership_ReturnPhoneNumberCannotByEmpty_WhenEmptyPhone(string phone)
    {
        // Arrange
        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumber", phone);
        
        // Act
        LoginMembershipResult? result = await DbFixture.Connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );
        
        // Assert
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

    [TestMethod]
    public async Task LoginMembership_ReturnInactiveMembership_WhenMembershipNotActive()
    {
        // Arrange 
        await DataSeeder.Build(DbFixture.Connection)
            .WithPhone("+380500000000")
            .WithAppDevice()
            .WithVerificationFlow()
            .WithMembership(secureKey: [0x00])
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
        Assert.AreEqual("inactive_membership", result.Outcome);
    }
    
    [TestMethod]
    public async Task LoginMembership_ReturnSuccess_WhenValidPhoneAndMembership()
    {
        // Arrange
        await DataSeeder.Build(DbFixture.Connection)
            .WithPhone("+380500000000")
            .WithAppDevice()
            .WithVerificationFlow()
            .WithMembership(secureKey: [0x01], status: "active")
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
        Assert.IsNotNull(result.MembershipUniqueId);
        Assert.AreEqual("success", result.Outcome);
        Assert.IsTrue(result.SecureKey.Length > 0);
    }
}