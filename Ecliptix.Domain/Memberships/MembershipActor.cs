using Akka.Actor;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Persistors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Extensions.Localization;

namespace Ecliptix.Domain.Memberships;

public record UpdateMembershipSecureKeyEvent(Guid MembershipIdentifier, byte[] SecureKey);

public class MembershipActor : ReceiveActor
{
    private readonly IActorRef _persistor;
    private readonly IStringLocalizer<MembershipActor> _localizer;

    private const string InvalidCredentials = "invalid_credentials";

    private const string MinutesUntilLoginRetry = "minutes_until_login_retry";

    public MembershipActor(IActorRef persistor, IStringLocalizer<MembershipActor> localizer)
    {
        _persistor = persistor;
        _localizer = localizer;

        Become(Ready);
    }

    public static Props Build(IActorRef persistor, IStringLocalizer<MembershipActor> localizer) =>
        Props.Create(() => new MembershipActor(persistor, localizer));

    private void Ready()
    {
        ReceiveAsync<UpdateMembershipSecureKeyEvent>(HandleUpdateMembershipSecureKeyCommand);
        ReceiveAsync<CreateMembershipActorEvent>(HandleCreateMembershipActorCommand);
        ReceiveAsync<SignInMembershipActorEvent>(HandleSignInMembershipActorCommand);
    }

    private async Task HandleUpdateMembershipSecureKeyCommand(UpdateMembershipSecureKeyEvent @event)
    {
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> operationResult =
            await _persistor.Ask<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>(@event);

        Result<UpdateMembershipWithSecureKeyResponse, VerificationFlowFailure> result = operationResult.Match(
            ok: option => option.Match(
                record =>
                {
                    UpdateMembershipWithSecureKeyResponse updateMembershipWithSecureKeyResponse =
                        new()
                        {
                            Membership = new Membership
                            {
                                UniqueIdentifier = Helpers.GuidToByteString(record.UniqueIdentifier),
                                Status = record.ActivityStatus,
                                CreationStatus = record.CreationStatus
                            },
                            Result = UpdateMembershipWithSecureKeyResponse.Types.UpdateResult.Succeeded
                        };

                    return Result<UpdateMembershipWithSecureKeyResponse, VerificationFlowFailure>.Ok(
                        updateMembershipWithSecureKeyResponse);
                },
                () => Result<UpdateMembershipWithSecureKeyResponse, VerificationFlowFailure>.Ok(
                    new UpdateMembershipWithSecureKeyResponse
                    {
                        Result = UpdateMembershipWithSecureKeyResponse.Types.UpdateResult.InvalidCredentials,
                        Message = _localizer[InvalidCredentials].Value
                    })
            ),
            Result<UpdateMembershipWithSecureKeyResponse, VerificationFlowFailure>.Err);

        Sender.Tell(result);
    }

    private async Task HandleCreateMembershipActorCommand(CreateMembershipActorEvent @event)
    {
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> operationResult =
            await _persistor.Ask<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>(@event);
        Sender.Tell(operationResult);
    }

    private async Task HandleSignInMembershipActorCommand(SignInMembershipActorEvent @event)
    {
        Result<Option<MembershipQueryRecord>, VerificationFlowFailure> result =
            await _persistor.Ask<Result<Option<MembershipQueryRecord>, VerificationFlowFailure>>(@event);

        Result<SignInMembershipResponse, VerificationFlowFailure> operationResult = result.Match(
            ok: option => option.Match(
                record => Result<SignInMembershipResponse, VerificationFlowFailure>.Ok(
                    new SignInMembershipResponse
                    {
                        Membership = new Membership
                        {
                            UniqueIdentifier = Helpers.GuidToByteString(record.UniqueIdentifier),
                            Status = record.ActivityStatus
                        },
                        Result = SignInMembershipResponse.Types.SignInResult.Succeeded
                    }
                ),
                () => Result<SignInMembershipResponse, VerificationFlowFailure>.Ok(
                    new SignInMembershipResponse
                    {
                        Result = SignInMembershipResponse.Types.SignInResult.InvalidCredentials,
                        Message = _localizer[InvalidCredentials].Value
                    }
                )
            ),
            err =>
            {
                if (err.FailureType == VerificationFlowFailureType.Validation)
                {
                    return Result<SignInMembershipResponse, VerificationFlowFailure>.Ok(
                        new SignInMembershipResponse
                        {
                            Result = SignInMembershipResponse.Types.SignInResult.InvalidCredentials,
                            Message = _localizer[MinutesUntilLoginRetry].Value,
                            MinutesUntilRetry = err.Message
                        }
                    );
                }

                return Result<SignInMembershipResponse, VerificationFlowFailure>.Err(err);
            }
        );

        Sender.Tell(operationResult);
    }
}