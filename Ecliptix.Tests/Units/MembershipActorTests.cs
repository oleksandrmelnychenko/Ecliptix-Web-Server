using Akka.Actor;
using Akka.TestKit;
using Akka.TestKit.Xunit2;
using Ecliptix.Domain;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.OPAQUE;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Moq;

namespace Ecliptix.Tests.Units;

[TestClass]
public sealed class MembershipActorTests : TestKit
{
    private Mock<IOpaqueProtocolService> _opaqueMock;
    private TestProbe _persistorProbe;
    private IActorRef _membershipActor;
    
    [TestInitialize]
    public void Setup()
    {
        _persistorProbe = CreateTestProbe();
        _opaqueMock = new Mock<IOpaqueProtocolService>();

        var localizationMock = new Mock<ILocalizationProvider>();
        localizationMock.Setup(x => x.Localize("InvalidCredentials", It.IsAny<string>())).Returns("invalid");
        localizationMock.Setup(x => x.Localize("TooManySigninAttempts", It.IsAny<string>())).Returns("rate-limit");

        _membershipActor = Sys.ActorOf(MembershipActor.Build(_persistorProbe.Ref, _opaqueMock.Object, localizationMock.Object));
    }


    [TestMethod]
    [DataRow(null, false, OpaqueSignInInitResponse.Types.SignInResult.Succeeded, DisplayName = "Returns_Ok_When_All_Succeed")]
    [DataRow(null, true, null, DisplayName = "Returns_InvalidOpaque_When_InitiateSignIn_Fails")]
    [DataRow(VerificationFlowFailureType.Validation, false, OpaqueSignInInitResponse.Types.SignInResult.InvalidCredentials, DisplayName = "Returns_TranslatedFailure_When_Persistor_Fails_Validation")]
    [DataRow(VerificationFlowFailureType.RateLimitExceeded, false, OpaqueSignInInitResponse.Types.SignInResult.LoginAttemptExceeded, DisplayName = "Returns_TranslatedFailure_When_Persistor_Fails_RateLimit")]
    [DataRow(VerificationFlowFailureType.Generic, false, null, DisplayName = "Returns_Err_When_Persistor_Fails_Unexpectedly")]
    public void HandleSignInMembership_Handles_AllCases(object? failureTypeObj, bool opaqueShouldFail, object? expectedResultObj)

    {
         // Arrange
         SignInMembershipActorEvent @event = new
        (
            PhoneNumber: "+380500000000",
            OpaqueSignInInitRequest: new OpaqueSignInInitRequest(),
            CultureName: "uk-UA"
        );

        if (failureTypeObj is null)
        {
            // Success persistor
            var membershipRecord = new MembershipQueryRecord
            {
                SecureKey = new byte[] { 1, 2, 3 },
                UniqueIdentifier = Guid.NewGuid(),
                ActivityStatus = Membership.Types.ActivityStatus.Active,
                CreationStatus = Membership.Types.CreationStatus.PassphraseSet
            };

            Result<OpaqueSignInInitResponse, OpaqueFailure> opaqueResult = opaqueShouldFail
                ? Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(OpaqueFailure.InvalidInput("failed"))
                : Result<OpaqueSignInInitResponse, OpaqueFailure>.Ok(new OpaqueSignInInitResponse
                {
                    Result = OpaqueSignInInitResponse.Types.SignInResult.Succeeded,
                    Message = "ok"
                });

            _opaqueMock
                .Setup(x => x.InitiateSignIn(It.IsAny<OpaqueSignInInitRequest>(), It.IsAny<MembershipOpaqueQueryRecord>()))
                .Returns(opaqueResult);

            _membershipActor.Tell(@event, TestActor);

            _persistorProbe.ExpectMsg<SignInMembershipActorEvent>();
            _persistorProbe.Sender.Tell(Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(membershipRecord));
        }
        else
        {
            // Failure persistor
            Console.WriteLine("1");
            VerificationFlowFailureType failureType = (VerificationFlowFailureType)failureTypeObj;
            Console.WriteLine("2");
            VerificationFlowFailure failure = new VerificationFlowFailure(failureType, "msg");

            Console.WriteLine("3");
            _membershipActor.Tell(@event, TestActor);
            Console.WriteLine("4");
            _persistorProbe.ExpectMsg<SignInMembershipActorEvent>();
            Console.WriteLine("5");
            _persistorProbe.Sender.Tell(Result<MembershipQueryRecord, VerificationFlowFailure>.Err(failure));
            Console.WriteLine("6");
        }

        // Assert
        Console.WriteLine("7");
        Result<OpaqueSignInInitResponse, VerificationFlowFailure> result =
            ExpectMsg<Result<OpaqueSignInInitResponse, VerificationFlowFailure>>();

        if (expectedResultObj is null)
        {
            Assert.IsTrue(result.IsErr);
        }
        else
        {
            Assert.IsTrue(result.IsOk);
            Assert.AreEqual((OpaqueSignInInitResponse.Types.SignInResult)expectedResultObj, result.Unwrap().Result);
        }
    }
}