using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Serilog;

namespace Ecliptix.Domain.Memberships.WorkerActors;

public record UpdateMembershipSecureKeyEvent(Guid MembershipIdentifier, byte[] SecureKey);

public class MembershipActor : ReceiveActor
{
    private readonly ILocalizationProvider _localizationProvider;
    private readonly IActorRef _persistor;

    public MembershipActor(IActorRef persistor, ILocalizationProvider localizationProvider)
    {
        _persistor = persistor;
        _localizationProvider = localizationProvider;

        Become(Ready);
    }

    public static Props Build(IActorRef persistor, ILocalizationProvider localizationProvider)
    {
        return Props.Create(() => new MembershipActor(persistor, localizationProvider));
    }

    private void Ready()
    {
        ReceiveAsync<UpdateMembershipSecureKeyEvent>(HandleUpdateMembershipSecureKeyCommand);
        ReceiveAsync<CreateMembershipActorEvent>(HandleCreateMembership);
        ReceiveAsync<SignInMembershipActorEvent>(HandleSignInMembership);
    }

    private async Task HandleUpdateMembershipSecureKeyCommand(UpdateMembershipSecureKeyEvent @event)
    {
        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(@event);

        Result<UpdateMembershipWithSecureKeyResponse, VerificationFlowFailure> finalResult =
            persistorResult.Map(record => new UpdateMembershipWithSecureKeyResponse
            {
                Membership = new Membership
                {
                    UniqueIdentifier = Helpers.GuidToByteString(record.UniqueIdentifier),
                    Status = record.ActivityStatus,
                    CreationStatus = record.CreationStatus
                },
                Result = UpdateMembershipWithSecureKeyResponse.Types.UpdateResult.Succeeded
            });

        Sender.Tell(finalResult);
    }

    private async Task HandleCreateMembership(CreateMembershipActorEvent @event)
    {
        Result<MembershipQueryRecord, VerificationFlowFailure> operationResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(@event);
        Sender.Tell(operationResult);
    }

    private async Task HandleSignInMembership(SignInMembershipActorEvent @event)
    {
        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(@event);

        Result<SignInMembershipResponse, VerificationFlowFailure> finalResult = persistorResult.Match(
            record =>
            {
                SignInMembershipResponse successResponse = new()
                {
                    Membership = new Membership
                    {
                        UniqueIdentifier = Helpers.GuidToByteString(record.UniqueIdentifier),
                        Status = record.ActivityStatus
                    },
                    Result = SignInMembershipResponse.Types.SignInResult.Succeeded
                };
                return Result<SignInMembershipResponse, VerificationFlowFailure>.Ok(successResponse);
            },
            failure => TranslateSignInFailure(failure, @event.CultureName));

        Sender.Tell(finalResult);
    }

    private Result<SignInMembershipResponse, VerificationFlowFailure> TranslateSignInFailure(
        VerificationFlowFailure failure,
        string cultureName)
    {
        switch (failure.FailureType)
        {
            case VerificationFlowFailureType.Validation:
            case VerificationFlowFailureType.NotFound:
            {
                string message = _localizationProvider.Localize(
                    VerificationFlowMessageKeys.InvalidCredentials,
                    cultureName
                );
                return Result<SignInMembershipResponse, VerificationFlowFailure>.Ok(new SignInMembershipResponse
                {
                    Result = SignInMembershipResponse.Types.SignInResult.InvalidCredentials,
                    Message = message
                });
            }

            case VerificationFlowFailureType.RateLimitExceeded:
            {
                string message = _localizationProvider.Localize(
                    VerificationFlowMessageKeys.TooManySigninAttempts,
                    cultureName
                );
                return Result<SignInMembershipResponse, VerificationFlowFailure>.Ok(new SignInMembershipResponse
                {
                    Result = SignInMembershipResponse.Types.SignInResult.LoginAttemptExceeded,
                    Message = message,
                    MinutesUntilRetry = "5"
                });
            }

            default:
                return Result<SignInMembershipResponse, VerificationFlowFailure>
                    .Err(failure);
        }
    }
}