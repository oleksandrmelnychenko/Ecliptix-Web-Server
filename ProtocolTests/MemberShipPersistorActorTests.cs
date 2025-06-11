/*using System.Data;
using System.Data.Common;
using Akka.Actor;
using Akka.TestKit;
using Akka.TestKit.MsTest;
using Ecliptix.Domain;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.Utilities;
using Ecliptix.Domain.Utilities;
using Microsoft.Extensions.Logging;
using Moq;
using Npgsql;

namespace ProtocolTests;

[TestClass]
public class MemberShipPersistorActorTests : TestKit
{
    private static readonly SignInMembershipActorEvent SignInEvent = new (
        PhoneNumber: "+380501234567",
        SecureKey: [1, 2, 3, 4, 5, 6, 7, 8, 9],"");
    
    [TestMethod]
    public async Task HandleSignInMembershipActorCommand_ReturnSuccess_WhenValidCredentials()
    {
        // Arrange
        Guid expectedGuid = Guid.NewGuid();
        
        IActorRef actor = CreateMockedActor(
            isDbNull0: false,
            expectedGuid: expectedGuid,
            status: "active",
            outcome: VerificationFlowMessageKeys.Success,
            readAsyncResult: true);

        // Act
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> result =
            await actor.Ask<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>(SignInEvent,
                TimeSpan.FromSeconds(3));

        // Assert
        Assert.IsTrue(result.IsOk, "Result Should Be Ok");
        Option<MembershipQueryRecord> membership = result.Unwrap();
        Assert.IsTrue(membership.HasValue, "Membership Should Have A Value");
        Assert.AreEqual(expectedGuid, membership.Value?.UniqueIdentifier, "UniqueIdentifier Should Match Expected Value");
    }

    [TestMethod]
    public async Task HandleSignInMembershipActorCommand_ReturnNone_WhenMembershipNotFound()
    {
        // Arrange
        IActorRef actor = CreateMockedActor(
            isDbNull0: true,
            expectedGuid: Guid.Empty,
            status: null,
            outcome: VerificationFlowMessageKeys.MembershipNotFound,
            readAsyncResult: true);

        // Act
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> result =
            await actor.Ask<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>(SignInEvent,
                TimeSpan.FromSeconds(3));
        
        //Assert 
        Assert.IsTrue(result.IsOk, "Result Should Be Ok");
        Option<MembershipQueryRecord> membership = result.Unwrap();
        Assert.IsTrue(!membership.HasValue, "Membership Shouldn't Have A Value"); 
    }

    [TestMethod]
    public async Task HandleSignInMembershipActorCommand_ReturnNone_WhenPhoneNotFound()
    {
        // Arrange
        IActorRef actor = CreateMockedActor(
            isDbNull0: true,
            expectedGuid: Guid.Empty,
            status: null,
            outcome: VerificationFlowMessageKeys.PhoneNotFound,
            readAsyncResult: true);

        // Act
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> result =
            await actor.Ask<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>(SignInEvent,
                TimeSpan.FromSeconds(3));
        
        //Assert 
        Assert.IsTrue(result.IsOk, "Result Should Be Ok");
        Option<MembershipQueryRecord> membership = result.Unwrap();
        Assert.IsTrue(!membership.HasValue, "Membership Shouldn't Have A Value");
    }
    
    [TestMethod]
    public async Task HandleSignInMembershipActorCommand_ReturnNone_WhenKnownLoginError()
    {
        // Arrange
        IActorRef actor = CreateMockedActor(
            isDbNull0: true,
            expectedGuid: Guid.Empty,
            status: "active",
            outcome: VerificationFlowMessageKeys.InvalidSecureKey,
            readAsyncResult: true);

        // Act
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> result =
            await actor.Ask<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>(SignInEvent,
                TimeSpan.FromSeconds(3));
        
        //Assert 
        Assert.IsTrue(result.IsErr, "Result Should Be Error");
        VerificationFlowFailure error = result.UnwrapErr();
        Assert.AreEqual(error.ErrorCode, "VF501", "Error Code Should Match Expected Value");
        Assert.AreEqual(error.Message, "invalid_secure_key", "Error Message Should Match Expected Value");
        Assert.AreEqual(error.FailureType, VerificationFlowFailureType.Validation, "FailureType Should Be Validation");
    }

    [TestMethod]
    public async Task HandleSignInMembershipActorCommand_ReturnTooManySigninAttempts_WhenOutcomeIsNumeric()
    {
        // Arrange
        IActorRef actor = CreateMockedActor(
            isDbNull0: true,
            expectedGuid: Guid.Empty,
            status: "active",
            outcome: "429",
            readAsyncResult: true);

        // Act
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> result =
            await actor.Ask<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>(SignInEvent,
                TimeSpan.FromSeconds(3));
        
        //Assert 
        Assert.IsTrue(result.IsErr, "Result Should Be Error");
        VerificationFlowFailure error = result.UnwrapErr();
        Assert.AreEqual(error.ErrorCode, "VF401", "Error Code Should Match Expected Value");
        Assert.AreEqual(error.Message, "signin_too_many_attempts", "Error Message Should Match Expected Value");
        Assert.AreEqual(error.FailureType, VerificationFlowFailureType.RateLimitExceeded, "FailureType Should Be RateLimitExceeded");
    }

    [TestMethod]
    public async Task HandleSignInMembershipActorCommand_ReturnPersistorError_WhenReadAsyncReturnsFalse()
    {
        // Arrange
        IActorRef actor = CreateMockedActor(
            isDbNull0: true,
            expectedGuid: Guid.Empty,
            status: "active",
            outcome: VerificationFlowMessageKeys.Success,
            readAsyncResult: false);

        // Act
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> result =
            await actor.Ask<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>(SignInEvent,
                TimeSpan.FromSeconds(3));
        
        //Assert 
        Assert.IsTrue(result.IsErr, "Result Should Be Error");
        VerificationFlowFailure error = result.UnwrapErr();
        Assert.AreEqual(error.ErrorCode, "VF301", "Error Code Should Match Expected Value");
        Assert.AreEqual(error.Message, "data_access_failed", "Error Message Should Match Expected Value");
        Assert.AreEqual(error.FailureType, VerificationFlowFailureType.PersistorAccess, "FailureType Should Be PersistorAccess");
    }

    [TestMethod]
    public async Task HandleSignInMembershipActorCommand_ReturnPersistorError_WhenActivityStatusIsInvalid()
    {
        // Arrange
        IActorRef actor = CreateMockedActor(
            isDbNull0: false,
            expectedGuid: Guid.NewGuid(),
            status: "invalid_status",
            outcome: VerificationFlowMessageKeys.Success,
            readAsyncResult: true);
        
        // Act
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> result =
            await actor.Ask<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>(SignInEvent,
                TimeSpan.FromSeconds(3));
        
        //Assert
        Assert.IsTrue(result.IsErr, "Result Should Be Error");
        VerificationFlowFailure error = result.UnwrapErr();
        Assert.AreEqual(error.ErrorCode, "VF301", "Error Code Should Match Expected Value");
        Assert.AreEqual(error.Message, "activity_status_invalid", "Error Message Should Match Expected Value");
        Assert.AreEqual(error.FailureType, VerificationFlowFailureType.PersistorAccess, "FailureType Should Be PersistorAccess");
    }

    [TestMethod]
    public async Task HandleSignInMembershipActorCommand_ReturnPersistorError_WhenOutcomeIsUnexpected()
    {
        // Arrange
        IActorRef actor = CreateMockedActor(
            isDbNull0: false,
            expectedGuid: Guid.NewGuid(),
            status: "active",
            outcome: "unexpected_outcome",
            readAsyncResult: true);
        
        // Act
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> result =
            await actor.Ask<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>(SignInEvent,
                TimeSpan.FromSeconds(3));
        
        //Assert
        Assert.IsTrue(result.IsErr, "Result Should Be Error");
        VerificationFlowFailure error = result.UnwrapErr();
        Assert.AreEqual(error.ErrorCode, "VF301", "Error Code Should Match Expected Value");
        Assert.AreEqual(error.Message, "unexpected_outcome", "Error Message Should Match Expected Value");
        Assert.AreEqual(error.FailureType, VerificationFlowFailureType.PersistorAccess, "FailureType Should Be PersistorAccess");
    }
    
    [TestMethod]
    public async Task HandleSignInMembershipActorCommand_UsesCorrectQueryAndParameters()
    {
        // Arrange
        string expectedQuery = Queries.LoginMembership;

        Mock<ILogger<MembershipPersistorActor>> mockLogger = new ();

        Mock<IDbDataReader> mockReader = new ();
        mockReader.Setup(r => r.ReadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        Mock<IDbCommand> mockCommand = new ();
        mockCommand.SetupProperty(c => c.CommandText);
        mockCommand.Setup(c => c.ExecuteReaderAsync(It.IsAny<CancellationToken>()))
                   .ReturnsAsync(mockReader.Object);

        Mock<DbParameterCollection> parameterCollection = new ();
        List<IDataParameter> capturedParameters = new ();
        parameterCollection.Setup(p => p.Add(It.IsAny<object>())).Callback<object>(p =>
        {
            if (p is IDataParameter param)
                capturedParameters.Add(param);
        }).Returns(0);

        mockCommand.Setup(c => c.Parameters).Returns(parameterCollection.Object);

        Mock<IDbConnection> mockConnection = new ();
        mockConnection.Setup(c => c.CreateCommand()).Returns(mockCommand.Object);

        Mock<IDbDataSource> mockDataSource = new ();
        mockDataSource.Setup(d => d.CreateConnection(It.IsAny<CancellationToken>()))
                      .ReturnsAsync(mockConnection.Object);

        IActorRef? actor = Sys.ActorOf(MembershipPersistorActor.Build(mockDataSource.Object, mockLogger.Object));

        // Act
        actor.Tell(SignInEvent ,TestActor);
        await ExpectMsgAsync<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>(); // wait for completion

        // Assert
        Assert.AreEqual(expectedQuery, mockCommand.Object.CommandText);
        Assert.IsTrue(capturedParameters.Any(p => p.ParameterName == "phone_number" 
                                                  && (string)p.Value! == SignInEvent.PhoneNumber));
        Assert.IsTrue(capturedParameters.Any(p => p.ParameterName == "secure_key" 
                                                  && ((byte[])p.Value!).SequenceEqual(SignInEvent.SecureKey)));
        
        mockCommand.Verify(c => c.ExecuteReaderAsync(It.IsAny<CancellationToken>()), Times.Once);
    }
    
    [TestMethod]
    public async Task HandleSignInMembershipActorCommand_ReturnPersistorError_WhenExecuteReaderThrows()
    {
        // Arrange
        Mock<ILogger<MembershipPersistorActor>> mockLogger = new ();
        
        Mock<IDbDataReader> mockReader = new();
        mockReader.Setup(r => r.ReadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(true);
        
        Mock<IDbCommand> mockCommand = new ();
        mockCommand.Setup(c => c.ExecuteReaderAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new NpgsqlException("Database error."));
     
        Mock<DbParameterCollection> parameterCollectionMock = new ();
        parameterCollectionMock.Setup(pc => pc.Add(It.IsAny<object>())).Returns(0);
        mockCommand.Setup(c => c.Parameters).Returns(parameterCollectionMock.Object);
        
        Mock<IDbConnection> mockConnection = new ();
        mockConnection.Setup(c => c.CreateCommand()).Returns(mockCommand.Object);
        
        Mock<IDbDataSource> dataSourceMock = new ();
        dataSourceMock
            .Setup(d => d.CreateConnection(It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockConnection.Object);

        IActorRef actor = Sys.ActorOf(MembershipPersistorActor.Build(dataSourceMock.Object, mockLogger.Object));

        TestProbe? probe = CreateTestProbe();
        SignInMembershipActorEvent cmd = SignInEvent;

        // Act
        actor.Tell(cmd, probe.Ref);

        // Assert
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> response 
            = await probe.ExpectMsgAsync<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>();
        Assert.IsTrue(response.IsErr);
        VerificationFlowFailure error = response.UnwrapErr();

        Assert.AreEqual(VerificationFlowFailureType.PersistorAccess, response.UnwrapErr().FailureType);
        Assert.AreEqual(error.ErrorCode, "VF301", "Error Code Should Match Expected Value");
        Assert.AreEqual(error.Message, "data_access_failed", "Error Message Should Match Expected Value");

        Assert.IsNotNull(error.InnerException, "Inner Exception Should Not Be Null");
        Assert.AreEqual(typeof(NpgsqlException), error.InnerException.GetType());
        Assert.AreEqual("Database error.", error.InnerException.Message, "Inner Exception Message Should Match");
    }  

    [TestMethod]
    public async Task HandleSignInMembershipActorCommand_ReturnPersistorError_WhenCreateCommandFails()
    {
        // Arrange
        Mock<ILogger<MembershipPersistorActor>> mockLogger = new ();
        
        Mock<IDbDataReader> mockReader = new();
        mockReader.Setup(r => r.ReadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(true);
        
        Mock<IDbCommand> mockCommand = new ();
        mockCommand.Setup(c => c.ExecuteReaderAsync(It.IsAny<CancellationToken>())).ReturnsAsync(mockReader.Object);
     
        Mock<DbParameterCollection> parameterCollectionMock = new ();
        parameterCollectionMock.Setup(pc => pc.Add(It.IsAny<object>())).Returns(0);
        mockCommand.Setup(c => c.Parameters).Returns(parameterCollectionMock.Object);
        
        Mock<IDbConnection> mockConnection = new ();
        mockConnection.Setup(c => c.CreateCommand()).Throws(new Exception("Broken command."));

        Mock<IDbDataSource> mockDataSource = new ();
        mockDataSource.Setup(ds => ds.CreateConnection(It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockConnection.Object);

        IActorRef? actor = Sys.ActorOf(MembershipPersistorActor.Build(mockDataSource.Object, mockLogger.Object));

        TestProbe? probe = CreateTestProbe();

        // Act
        actor.Tell(SignInEvent, probe.Ref);

        // Assert
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> response =
            await probe.ExpectMsgAsync<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>();
        Assert.IsTrue(response.IsErr);
        VerificationFlowFailure error = response.UnwrapErr();

        Assert.AreEqual(VerificationFlowFailureType.Generic, response.UnwrapErr().FailureType);
        Assert.AreEqual(error.ErrorCode, "VF999", "Error Code Should Match Expected Value");
        Assert.AreEqual(error.Message, "generic_error", "Error Message Should Match Expected Value");

        Assert.IsNotNull(error.InnerException, "Inner Exception Should Not Be Null");
        Assert.AreEqual(typeof(Exception), error.InnerException.GetType());
        Assert.AreEqual("Broken command.", error.InnerException.Message, "Inner Exception Message Should Match");
    }

    [TestMethod]
    public async Task HandleSignInMembershipActorCommand_ReturnPersistorError_WhenReadAsyncThrows()
    {
        // Arrange
        Mock<ILogger<MembershipPersistorActor>> mockLogger = new ();
        
        Mock<IDbDataReader> mockReader = new();
        mockReader.Setup(r => r.ReadAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Read failed."));
        
        Mock<IDbCommand> mockCommand = new ();
        mockCommand.Setup(c => c.ExecuteReaderAsync(It.IsAny<CancellationToken>())).ReturnsAsync(mockReader.Object);
     
        Mock<DbParameterCollection> parameterCollectionMock = new ();
        parameterCollectionMock.Setup(pc => pc.Add(It.IsAny<object>())).Returns(0);
        mockCommand.Setup(c => c.Parameters).Returns(parameterCollectionMock.Object);
        
        Mock<IDbConnection> mockConnection = new ();
        mockConnection.Setup(c => c.CreateCommand()).Returns(mockCommand.Object);

        Mock<IDbDataSource> mockDataSource = new ();
        mockDataSource.Setup(ds => ds.CreateConnection(It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockConnection.Object);

        IActorRef? actor = Sys.ActorOf(MembershipPersistorActor.Build(mockDataSource.Object, mockLogger.Object));

        TestProbe? probe = CreateTestProbe();

        // Act
        actor.Tell(SignInEvent, probe.Ref);

        // Assert
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> response =
            await probe.ExpectMsgAsync<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>();
        Assert.IsTrue(response.IsErr);
        VerificationFlowFailure error = response.UnwrapErr();

        Assert.AreEqual(VerificationFlowFailureType.Generic, response.UnwrapErr().FailureType);
        Assert.AreEqual(error.ErrorCode, "VF999", "Error Code Should Match Expected Value");
        Assert.AreEqual(error.Message, "generic_error", "Error Message Should Match Expected Value");

        Assert.IsNotNull(error.InnerException, "Inner Exception Should Not Be Null");
        Assert.AreEqual(typeof(Exception), error.InnerException.GetType());
        Assert.AreEqual("Read failed.", error.InnerException.Message, "Inner Exception Message Should Match");
    }
    
    private IActorRef CreateMockedActor(
        bool isDbNull0,
        Guid expectedGuid,
        string? status,
        string outcome,
        bool readAsyncResult = true)
    {
        Mock<ILogger<MembershipPersistorActor>> mockLogger = new ();
        
        Mock<IDbDataReader> mockReader = new();
        mockReader.Setup(r => r.IsDBNull(0)).Returns(isDbNull0);
        mockReader.Setup(r => r.GetGuid(0)).Returns(expectedGuid);
        mockReader.Setup(r => r.IsDBNull(1)).Returns(status == null);
        mockReader.Setup(r => r.GetString(2)).Returns(outcome);
        mockReader.Setup(r => r.ReadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(readAsyncResult);
        if (status != null)
        {
            mockReader.Setup(r => r.GetString(1)).Returns(status);
        }
        
        Mock<IDbCommand> mockCommand = new ();
        mockCommand.SetupAllProperties();
        mockCommand.SetupProperty(c => c.CommandText);
        mockCommand.Setup(c => c.ExecuteReaderAsync(It.IsAny<CancellationToken>())).ReturnsAsync(mockReader.Object);
     
        Mock<DbParameterCollection> parameterCollectionMock = new ();
        parameterCollectionMock.Setup(pc => pc.Add(It.IsAny<object>())).Returns(0);
        mockCommand.Setup(c => c.Parameters).Returns(parameterCollectionMock.Object);
        
        Mock<IDbConnection> mockConnection = new ();
        mockConnection.Setup(c => c.CreateCommand()).Returns(mockCommand.Object);
        
        Mock<IDbDataSource> dataSourceMock = new ();
        dataSourceMock
            .Setup(d => d.CreateConnection(It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockConnection.Object);
        
        IActorRef actor = Sys.ActorOf(MembershipPersistorActor.Build(dataSourceMock.Object, mockLogger.Object));

        return actor;
    }
}*/