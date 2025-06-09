using Akka.Actor;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Serilog;

namespace Ecliptix.Domain.Memberships;

public record UpdateMembershipSecureKeyEvent(Guid MembershipIdentifier, byte[] SecureKey, string CultureName);

public class MembershipActor : ReceiveActor
{
    private readonly IActorRef _persistor;
    private readonly ILocalizationProvider _localizationProvider;

    public MembershipActor(IActorRef persistor, ILocalizationProvider localizationProvider)
    {
        _persistor = persistor;
        _localizationProvider = localizationProvider;

        Become(Ready);
    }

    public static Props Build(IActorRef persistor, ILocalizationProvider localizationProvider) =>
        Props.Create(() => new MembershipActor(persistor, localizationProvider));

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
                        Message = _localizationProvider.Localize(VerificationFlowMessageKeys.InvalidCredentials,
                            @event.CultureName)
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
                        Message = _localizationProvider.Localize(VerificationFlowMessageKeys.InvalidCredentials,
                            @event.CultureName),
                    }
                )
            ),
            err =>
            {
                if (err.FailureType == VerificationFlowFailureType.Validation)
                {
                    string message;
                    
                    if (err.IsUserFacing)
                    {
                        message =_localizationProvider.Localize(err.Message);
                        Log.Information("Sign-in failed for {PhoneNumber} with error: {ErrorMessage}",
                            @event.PhoneNumber, message);
                    }
                    
                    message = _localizationProvider.Localize(VerificationFlowMessageKeys.InvalidCredentials,
                        @event.CultureName);

                    return Result<SignInMembershipResponse, VerificationFlowFailure>.Ok(
                        new SignInMembershipResponse
                        {
                            Result = SignInMembershipResponse.Types.SignInResult.InvalidCredentials,
                            Message = message,
                            MinutesUntilRetry = string.Empty
                        }
                    );
                }

                if (err.FailureType == VerificationFlowFailureType.RateLimitExceeded)
                {
                    
                }

                return Result<SignInMembershipResponse, VerificationFlowFailure>.Err(err);
            }
        );

        Sender.Tell(operationResult);
    }
}