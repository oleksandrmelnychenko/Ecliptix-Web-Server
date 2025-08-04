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
    
    private readonly SignInMembershipActorEvent signInEvent = new
    (
        PhoneNumber: "+380500000000",
        OpaqueSignInInitRequest: new OpaqueSignInInitRequest(),
        CultureName: "uk-UA"
    );

    [TestInitialize]
    public void Initialize()
    {
        _opaqueMock = new Mock<IOpaqueProtocolService>();
        _persistorProbe = CreateTestProbe();

        Mock<ILocalizationProvider> localizationMock = new();
        localizationMock.Setup(x => x.Localize(It.IsAny<string>(), It.IsAny<string>())).Returns("msg");
        
        _membershipActor = Sys.ActorOf(MembershipActor.Build(_persistorProbe.Ref, _opaqueMock.Object, localizationMock.Object));
    }
    
    [TestMethod]
    public async Task HandleSignInMembership_ReturnSuccess_WhenPersistorAndOpaqueSuccess()
    {
        MembershipQueryRecord membershipRecord = new()
        {
            SecureKey = [1, 2, 3, 4],
            UniqueIdentifier = Guid.NewGuid(),
            ActivityStatus = Membership.Types.ActivityStatus.Active,
            CreationStatus = Membership.Types.CreationStatus.SecureKeySet
        };

        OpaqueSignInInitResponse opaqueResponse = new()
        {
            Result = OpaqueSignInInitResponse.Types.SignInResult.Succeeded
        };
        
        _opaqueMock
            .Setup(x => x.InitiateSignIn(It.IsAny<OpaqueSignInInitRequest>(), It.IsAny<MembershipOpaqueQueryRecord>()))
            .Returns(Result<OpaqueSignInInitResponse, OpaqueFailure>.Ok(opaqueResponse));

        // Act
        _membershipActor.Tell(signInEvent, TestActor);

        _persistorProbe.ExpectMsg<SignInMembershipActorEvent>();
        _persistorProbe.Sender.Tell(Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(membershipRecord));

        // Assert
        var result = ExpectMsg<Result<OpaqueSignInInitResponse, VerificationFlowFailure>>();
        Assert.IsTrue(result.IsOk);
        Assert.AreEqual(OpaqueSignInInitResponse.Types.SignInResult.Succeeded, result.Unwrap().Result);
    }
}