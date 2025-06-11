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

    private async Task HandleCreateMembershipActorCommand(CreateMembershipActorEvent @event)
    {
        Result<MembershipQueryRecord, VerificationFlowFailure> operationResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(@event);
        Sender.Tell(operationResult);
    }

    private async Task HandleSignInMembershipActorCommand(SignInMembershipActorEvent @event)
    {
        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(@event);

        Result<SignInMembershipResponse, VerificationFlowFailure> finalResult = persistorResult.Match(
            ok: record => Result<SignInMembershipResponse, VerificationFlowFailure>.Ok(
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
            err: failure =>
            {
                switch (failure.FailureType)
                {
                    case VerificationFlowFailureType.Validation:
                    case VerificationFlowFailureType.NotFound:
                    {
                        string message = _localizationProvider.Localize(
                            VerificationFlowMessageKeys.InvalidCredentials,
                            @event.CultureName
                        );

                        Log.Information(
                            "Sign-in validation failed for {PhoneNumber} with internal error: {InternalError}",
                            @event.PhoneNumber, failure.Message);

                        return Result<SignInMembershipResponse, VerificationFlowFailure>.Ok(
                            new SignInMembershipResponse
                            {
                                Result = SignInMembershipResponse.Types.SignInResult.InvalidCredentials,
                                Message = message
                            }
                        );
                    }

                    case VerificationFlowFailureType.RateLimitExceeded:
                    {
                        string message = _localizationProvider.Localize(
                            VerificationFlowMessageKeys.TooManySigninAttempts,
                            @event.CultureName
                        );

                        Log.Warning(
                            "Sign-in rate limit exceeded for {PhoneNumber}. Wait for {Minutes} minutes.",
                            @event.PhoneNumber, failure.Message);

                        return Result<SignInMembershipResponse, VerificationFlowFailure>.Ok(
                            new SignInMembershipResponse
                            {
                                Result = SignInMembershipResponse.Types.SignInResult.LoginAttemptExceeded,
                                Message = message,
                                MinutesUntilRetry = failure.Message
                            }
                        );
                    }

                    case VerificationFlowFailureType.Expired:
                    case VerificationFlowFailureType.Conflict:
                    case VerificationFlowFailureType.InvalidOtp:
                    case VerificationFlowFailureType.OtpExpired:
                    case VerificationFlowFailureType.OtpMaxAttemptsReached:
                    case VerificationFlowFailureType.OtpGenerationFailed:
                    case VerificationFlowFailureType.SmsSendFailed:
                    case VerificationFlowFailureType.PhoneNumberInvalid:
                    case VerificationFlowFailureType.PersistorAccess:
                    case VerificationFlowFailureType.ConcurrencyConflict:
                    case VerificationFlowFailureType.SuspiciousActivity:
                    case VerificationFlowFailureType.Generic:
                    default:
                        return Result<SignInMembershipResponse, VerificationFlowFailure>.Err(failure);
                }
            }
        );

        Sender.Tell(finalResult);
    }
}