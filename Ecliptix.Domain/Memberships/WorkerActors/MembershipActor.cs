using Akka.Actor;
using Akka.IO;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.OPAQUE;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Serilog;
using ByteString = Google.Protobuf.ByteString;

namespace Ecliptix.Domain.Memberships.WorkerActors;

public record UpdateMembershipSecureKeyEvent(Guid MembershipIdentifier, byte[] SecureKey);

public record GenerateMembershipOprfRegistrationRequestEvent(Guid MembershipIdentifier, byte[] OprfRequest);
public record CompleteRegistrationRecordActorEvent(Guid MembershipIdentifier, byte[] PeerRegistrationRecord);
public record OprfInitRecoverySecureKeyEvent(Guid MembershipIdentifier, byte[] OprfRequest);
public record OprfCompleteRecoverySecureKeyEvent(Guid MembershipIdentifier, byte[] PeerRecoveryRecord);

public record SignInComplete(OpaqueSignInFinalizeRequest Request);

public class MembershipActor : ReceiveActor
{
    private readonly ILocalizationProvider _localizationProvider;
    private readonly IActorRef _persistor;
    private readonly IOpaqueProtocolService _opaqueProtocolService;

    public MembershipActor(IActorRef persistor, IOpaqueProtocolService opaqueProtocolService,
        ILocalizationProvider localizationProvider)
    {
        _persistor = persistor;
        _opaqueProtocolService = opaqueProtocolService;
        _localizationProvider = localizationProvider;

        Become(Ready);
    }

    public static Props Build(IActorRef persistor, IOpaqueProtocolService opaqueProtocolService,
        ILocalizationProvider localizationProvider)
    {
        return Props.Create(() => new MembershipActor(persistor, opaqueProtocolService, localizationProvider));
    }

    private void Ready()
    {
        Receive<SignInComplete>(updateEvent =>
        {
            Result<OpaqueSignInFinalizeResponse, OpaqueFailure> result =
                _opaqueProtocolService.FinalizeSignIn(updateEvent.Request);
            if (result.IsErr)
            {
                Sender.Tell(
                    Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.InvalidOpaque(result.UnwrapErr().Message)));
            }
            else
            {
                Sender.Tell(
                    Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Ok(result.Unwrap()));
            }
        });


        ReceiveAsync<GenerateMembershipOprfRegistrationRequestEvent>(HandleGenerateMembershipOprfRegistrationRecord);
        ReceiveAsync<CreateMembershipActorEvent>(HandleCreateMembership);
        ReceiveAsync<SignInMembershipActorEvent>(HandleSignInMembership);
        ReceiveAsync<CompleteRegistrationRecordActorEvent>(HandleCompleteRegistrationRecord);
        ReceiveAsync<OprfInitRecoverySecureKeyEvent>(HandleInitRecoveryRequestEvent);
        ReceiveAsync<OprfCompleteRecoverySecureKeyEvent>(HandleCompleteRecoverySecureKeyEvent);
    }

    private async Task HandleCompleteRegistrationRecord(CompleteRegistrationRecordActorEvent @event)
    {
        Result<Unit, OpaqueFailure> completionResult =
            _opaqueProtocolService.CompleteRegistration(@event.PeerRegistrationRecord);

        if (completionResult.IsErr)
        {
            Sender.Tell(Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque(completionResult.UnwrapErr().Message)));
            return;
        }

        UpdateMembershipSecureKeyEvent updateEvent = new(@event.MembershipIdentifier, @event.PeerRegistrationRecord);
        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(updateEvent);

        if (persistorResult.IsErr)
        {
            Sender.Tell(Result<Unit, VerificationFlowFailure>.Err(persistorResult.UnwrapErr()));
            return;
        }

        Sender.Tell(Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Ok(
            new OprfRegistrationCompleteResponse
            {
                Message = "Registration completed successfully."
            }));
    }

    private async Task HandleCompleteRecoverySecureKeyEvent(OprfCompleteRecoverySecureKeyEvent @event)
    {
        Result<Unit, OpaqueFailure> completionResult =
            _opaqueProtocolService.CompleteRegistration(@event.PeerRecoveryRecord);

        if (completionResult.IsErr)
        {
            Sender.Tell(Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque(completionResult.UnwrapErr().Message)));
            return;
        }
        
        UpdateMembershipSecureKeyEvent updateEvent = new(@event.MembershipIdentifier, @event.PeerRecoveryRecord);
        
        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(updateEvent);

        if (persistorResult.IsErr)
        {
            Sender.Tell(Result<Unit, VerificationFlowFailure>.Err(persistorResult.UnwrapErr()));
            return;
        }

        Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Ok(
            new OprfRecoverySecretKeyCompleteResponse()
            {
                Message = "Recovery secret key completed successfully."
            }));
    }

    private async Task HandleInitRecoveryRequestEvent(OprfInitRecoverySecureKeyEvent @event)
    {
        byte[] oprfResponse = _opaqueProtocolService.ProcessOprfRequest(@event.OprfRequest);

        UpdateMembershipSecureKeyEvent updateEvent = new(@event.MembershipIdentifier, oprfResponse);
        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(updateEvent);

        Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure> finalResult =
            persistorResult.Map(record => new OprfRecoverySecureKeyInitResponse
            {
                Membership = new Membership
                {
                    UniqueIdentifier = Helpers.GuidToByteString(record.UniqueIdentifier),
                    Status = record.ActivityStatus,
                    CreationStatus = record.CreationStatus
                },
                PeerOprf = ByteString.CopyFrom(oprfResponse),
                Result = OprfRecoverySecureKeyInitResponse.Types.RecoveryResult.Succeeded
            });

        Sender.Tell(finalResult);
    }
    
    private async Task HandleGenerateMembershipOprfRegistrationRecord(
        GenerateMembershipOprfRegistrationRequestEvent @event)
    {
        byte[] oprfResponse = _opaqueProtocolService.ProcessOprfRequest(@event.OprfRequest);

        UpdateMembershipSecureKeyEvent updateEvent = new(@event.MembershipIdentifier, oprfResponse);
        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(updateEvent);

        Result<OprfRegistrationInitResponse, VerificationFlowFailure> finalResult =
            persistorResult.Map(record => new OprfRegistrationInitResponse
            {
                Membership = new Membership
                {
                    UniqueIdentifier = Helpers.GuidToByteString(record.UniqueIdentifier),
                    Status = record.ActivityStatus,
                    CreationStatus = record.CreationStatus
                },
                PeerOprf = ByteString.CopyFrom(oprfResponse),
                Result = OprfRegistrationInitResponse.Types.UpdateResult.Succeeded
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

        Result<OpaqueSignInInitResponse, VerificationFlowFailure> finalResult = persistorResult.Match(
            record =>
            {
                Result<OpaqueSignInInitResponse, OpaqueFailure> initiateSignInResult =
                    _opaqueProtocolService.InitiateSignIn(
                        @event.OpaqueSignInInitRequest,
                        new MembershipOpaqueQueryRecord(@event.PhoneNumber, record.SecureKey));

                if (initiateSignInResult.IsErr)
                {
                    return Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Err(VerificationFlowFailure
                        .InvalidOpaque());
                }

                /*SignInMembershipResponse successResponse = new()
                {
                    Membership = new Membership
                    {
                        UniqueIdentifier = Helpers.GuidToByteString(record.UniqueIdentifier),
                        Status = record.ActivityStatus
                    },
                    Result = SignInMembershipResponse.Types.SignInResult.Succeeded
                };*/
                return Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Ok(initiateSignInResult.Unwrap());
            },
            failure => TranslateSignInFailure(failure, @event.CultureName));

        Sender.Tell(finalResult);
    }

    private Result<OpaqueSignInInitResponse, VerificationFlowFailure> TranslateSignInFailure(
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
                return Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Ok(new OpaqueSignInInitResponse
                {
                    Result = OpaqueSignInInitResponse.Types.SignInResult.InvalidCredentials,
                    Message = message
                });
            }

            case VerificationFlowFailureType.RateLimitExceeded:
            {
                string message = _localizationProvider.Localize(
                    VerificationFlowMessageKeys.TooManySigninAttempts,
                    cultureName
                );
                return Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Ok(new OpaqueSignInInitResponse
                {
                    Result = OpaqueSignInInitResponse.Types.SignInResult.LoginAttemptExceeded,
                    Message = message,
                    MinutesUntilRetry = 5
                });
            }

            default:
                return Result<OpaqueSignInInitResponse, VerificationFlowFailure>
                    .Err(failure);
        }
    }
}