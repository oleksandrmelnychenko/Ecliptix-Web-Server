using Akka.Actor;
using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships;

public record SignInMembershipActorCommand(string PhoneNumber, byte[] SecureKey);

public class MembershipActor : ReceiveActor
{
    private readonly IActorRef _persistor;

    private const string MembershipNotFoundMessageKey = "Membership not found.";

    public MembershipActor(IActorRef persistor)
    {
        _persistor = persistor;

        Become(Ready);
    }

    public static Props Build(IActorRef persistor) =>
        Props.Create(() => new MembershipActor(persistor));

    private void Ready()
    {
        Receive<CreateMembershipActorCommand>(HandleCreateMembershipActorCommand);
        ReceiveAsync<SignInMembershipActorCommand>(HandleSignInMembershipActorCommand);
    }

    private async Task HandleSignInMembershipActorCommand(SignInMembershipActorCommand command)
    {
        Result<Option<MembershipQueryRecord>, ShieldFailure> result =
            await _persistor.Ask<Result<Option<MembershipQueryRecord>, ShieldFailure>>(command);

        Result<SignInMembershipResponse, ShieldFailure> operationResult = result.Match(membershipQueryRecord =>
            {
                if (!membershipQueryRecord.HasValue)
                {
                    SignInMembershipResponse signInMembershipResponse = new()
                    {
                        Membership = new Membership(),
                        Result = SignInMembershipResponse.Types.SignInResult.InvalidCredentials,
                        Message = MembershipNotFoundMessageKey
                    };

                    return Result<SignInMembershipResponse, ShieldFailure>.Ok(signInMembershipResponse);
                }
                else
                {
                    SignInMembershipResponse signInMembershipResponse = new()
                    {
                        Membership = new Membership
                        {
                            UniqueIdentifier = Helpers.GuidToByteString(membershipQueryRecord.Value!.UniqueIdentifier),
                            Status = membershipQueryRecord.Value.Status
                        },
                        Result = SignInMembershipResponse.Types.SignInResult.Succeeded,
                    };

                    return Result<SignInMembershipResponse, ShieldFailure>.Ok(signInMembershipResponse);
                }
            },
            Result<SignInMembershipResponse, ShieldFailure>.Err);

        Sender.Tell(operationResult);
    }

    private void HandleCreateMembershipActorCommand(CreateMembershipActorCommand command)
    {
        _persistor.Forward(command);
    }
}