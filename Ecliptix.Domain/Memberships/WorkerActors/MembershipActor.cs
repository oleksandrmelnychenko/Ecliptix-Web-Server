using System.Security.Cryptography;
using Akka.Actor;
using Akka.IO;
using Ecliptix.Domain.Abstractions;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Membership;
using OprfRegistrationCompleteResponse = Ecliptix.Protobuf.Membership.OpaqueRegistrationCompleteResponse;
using OprfRecoverySecretKeyCompleteResponse = Ecliptix.Protobuf.Membership.OpaqueRecoverySecretKeyCompleteResponse;
using OprfRecoverySecureKeyInitResponse = Ecliptix.Protobuf.Membership.OpaqueRecoverySecureKeyInitResponse;
using OprfRegistrationInitResponse = Ecliptix.Protobuf.Membership.OpaqueRegistrationInitResponse;
using OprfRegistrationCompleteRequest = Ecliptix.Protobuf.Membership.OpaqueRegistrationCompleteRequest;
using OprfRecoverySecretKeyCompleteRequest = Ecliptix.Protobuf.Membership.OpaqueRecoverySecretKeyCompleteRequest;
using Serilog;
using ByteString = Google.Protobuf.ByteString;

namespace Ecliptix.Domain.Memberships.WorkerActors;

public record UpdateMembershipSecureKeyEvent(Guid MembershipIdentifier, byte[] SecureKey, byte[] MaskingKey);

public record GenerateMembershipOprfRegistrationRequestEvent(Guid MembershipIdentifier, byte[] OprfRequest);

public record CompleteRegistrationRecordActorEvent(Guid MembershipIdentifier, byte[] PeerRegistrationRecord, uint ConnectId);

public record OprfInitRecoverySecureKeyEvent(Guid MembershipIdentifier, byte[] OprfRequest);

public record OprfCompleteRecoverySecureKeyEvent(Guid MembershipIdentifier, byte[] PeerRecoveryRecord);

public record SignInCompleteEvent(uint ConnectId, OpaqueSignInFinalizeRequest Request);

public class MembershipActor : ReceiveActor
{
    private readonly ILocalizationProvider _localizationProvider;
    private readonly IActorRef _persistor;
    private readonly IActorRef _authContextPersistor;
    private readonly IOpaqueProtocolService _opaqueProtocolService;
    private readonly IActorRef _authenticationStateManager;
    private readonly ISessionKeyService _sessionKeyService;

    private readonly
        Dictionary<uint, (Guid MembershipId, Guid MobileNumberId, string MobileNumber, Membership.Types.ActivityStatus
            ActivityStatus, Membership.Types.CreationStatus CreationStatus, DateTime CreatedAt, byte[] ServerMac)>
        _pendingSignIns = new();

    private readonly Dictionary<Guid, byte[]> _pendingMaskingKeys = new();

    private static readonly TimeSpan PendingSignInTimeout = TimeSpan.FromMinutes(10);
    private ICancelable? _cleanupTimer;

    public MembershipActor(IActorRef persistor, IActorRef authContextPersistor,
        IOpaqueProtocolService opaqueProtocolService,
        ILocalizationProvider localizationProvider, IActorRef authenticationStateManager,
        ISessionKeyService sessionKeyService)
    {
        _persistor = persistor;
        _authContextPersistor = authContextPersistor;
        _opaqueProtocolService = opaqueProtocolService;
        _localizationProvider = localizationProvider;
        _authenticationStateManager = authenticationStateManager;
        _sessionKeyService = sessionKeyService;

        Become(Ready);
    }

    public static Props Build(IActorRef persistor, IActorRef authContextPersistor,
        IOpaqueProtocolService opaqueProtocolService,
        ILocalizationProvider localizationProvider, IActorRef authenticationStateManager,
        ISessionKeyService sessionKeyService)
    {
        return Props.Create(() => new MembershipActor(persistor, authContextPersistor, opaqueProtocolService,
            localizationProvider, authenticationStateManager, sessionKeyService));
    }

    protected override void PreStart()
    {
        base.PreStart();
        _cleanupTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
            TimeSpan.FromMinutes(5),
            TimeSpan.FromMinutes(5),
            Self,
            new CleanupExpiredPendingSignIns(),
            ActorRefs.NoSender);
    }

    protected override void PostStop()
    {
        _cleanupTimer?.Cancel();
        _pendingSignIns.Clear();

        foreach (byte[] maskingKey in _pendingMaskingKeys.Values)
        {
            CryptographicOperations.ZeroMemory(maskingKey);
        }
        _pendingMaskingKeys.Clear();

        base.PostStop();
    }

    private void Ready()
    {
        ReceiveAsync<SignInCompleteEvent>(HandleSignInComplete);
        Receive<CleanupExpiredPendingSignIns>(_ => CleanupExpiredPendingSignIns());
        ReceiveAsync<GenerateMembershipOprfRegistrationRequestEvent>(HandleGenerateMembershipOprfRegistrationRecord);
        ReceiveAsync<CreateMembershipActorEvent>(HandleCreateMembership);
        ReceiveAsync<SignInMembershipActorEvent>(HandleSignInMembership);
        ReceiveAsync<CompleteRegistrationRecordActorEvent>(HandleCompleteRegistrationRecord);
        ReceiveAsync<OprfInitRecoverySecureKeyEvent>(HandleInitRecoveryRequestEvent);
        ReceiveAsync<OprfCompleteRecoverySecureKeyEvent>(HandleCompleteRecoverySecureKeyEvent);
    }

    private async Task HandleCompleteRegistrationRecord(CompleteRegistrationRecordActorEvent @event)
    {
        if (!_pendingMaskingKeys.TryGetValue(@event.MembershipIdentifier, out byte[]? maskingKey))
        {
            Sender.Tell(Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque("No masking key found for membership during registration completion")));
            return;
        }

        Result<byte[], OpaqueFailure> completionResult =
            _opaqueProtocolService.CompleteRegistrationWithSessionKey(@event.PeerRegistrationRecord);

        if (completionResult.IsErr)
        {
            _pendingMaskingKeys.Remove(@event.MembershipIdentifier);
            Sender.Tell(Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque(completionResult.UnwrapErr().Message)));
            return;
        }

        //TODO: REMOVE.
        byte[] sessionKey = completionResult.Unwrap();

        UpdateMembershipSecureKeyEvent updateEvent = new(@event.MembershipIdentifier, @event.PeerRegistrationRecord, maskingKey);
        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(updateEvent);

        if (persistorResult.IsErr)
        {
            _pendingMaskingKeys.Remove(@event.MembershipIdentifier);
            Sender.Tell(Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Err(persistorResult.UnwrapErr()));
            return;
        }

        _pendingMaskingKeys.Remove(@event.MembershipIdentifier);

        try
        {
            Result<Unit, string> storeResult = await _sessionKeyService.StoreSessionKeyAsync(
                @event.ConnectId, sessionKey);

            if (storeResult.IsErr)
            {
                Log.Error("Failed to store session key for connectId {ConnectId}: {Error}",
                    @event.ConnectId, storeResult.UnwrapErr());
                Sender.Tell(Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess($"Failed to store session key: {storeResult.UnwrapErr()}")));
                return;
            }

            Log.Information("Session key stored successfully for connectId {ConnectId} after registration", @event.ConnectId);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error storing session key for connectId {ConnectId} during registration", @event.ConnectId);
            Sender.Tell(Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Failed to store session key: {ex.Message}")));
            return;
        }

        Sender.Tell(Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Ok(
            new OprfRegistrationCompleteResponse
            {
                Result = OprfRegistrationCompleteResponse.Types.RegistrationResult.Succeeded,
                Message = "Registration completed successfully.",
                SessionKey = ByteString.CopyFrom(sessionKey)
            }));

        CryptographicOperations.ZeroMemory(sessionKey);
    }

    private async Task HandleCompleteRecoverySecureKeyEvent(OprfCompleteRecoverySecureKeyEvent @event)
    {
        if (!_pendingMaskingKeys.TryGetValue(@event.MembershipIdentifier, out byte[]? maskingKey))
        {
            Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque("No masking key found for membership during recovery completion")));
            return;
        }

        /*
        Result<Unit, OpaqueFailure> completionResult =
            _opaqueProtocolService.CompleteRegistration(@event.PeerRecoveryRecord);

        if (completionResult.IsErr)
        {
            _pendingMaskingKeys.Remove(@event.MembershipIdentifier);
            Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque(completionResult.UnwrapErr().Message)));
            return;
        }
        */

        UpdateMembershipSecureKeyEvent updateEvent = new(@event.MembershipIdentifier, @event.PeerRecoveryRecord, maskingKey);

        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(updateEvent);

        if (persistorResult.IsErr)
        {
            _pendingMaskingKeys.Remove(@event.MembershipIdentifier);
            Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(persistorResult.UnwrapErr()));
            return;
        }

        _pendingMaskingKeys.Remove(@event.MembershipIdentifier);

        Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Ok(
            new OprfRecoverySecretKeyCompleteResponse()
            {
                Message = "Recovery secret key completed successfully."
            }));
    }

    private async Task HandleInitRecoveryRequestEvent(OprfInitRecoverySecureKeyEvent @event)
    {
        (byte[] oprfResponse, byte[] maskingKey) = _opaqueProtocolService.ProcessOprfRequest(@event.OprfRequest);

        _pendingMaskingKeys[@event.MembershipIdentifier] = maskingKey;

        UpdateMembershipSecureKeyEvent updateEvent = new(@event.MembershipIdentifier, oprfResponse, maskingKey);
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

    private Task HandleGenerateMembershipOprfRegistrationRecord(
        GenerateMembershipOprfRegistrationRequestEvent @event)
    {
        (byte[] oprfResponse, byte[] maskingKey) = _opaqueProtocolService.ProcessOprfRequest(@event.OprfRequest);

        _pendingMaskingKeys[@event.MembershipIdentifier] = maskingKey;

        OprfRegistrationInitResponse response = new()
        {
            Membership = new Membership
            {
                UniqueIdentifier = Helpers.GuidToByteString(@event.MembershipIdentifier),
                Status = Membership.Types.ActivityStatus.Inactive,
                CreationStatus = Membership.Types.CreationStatus.OtpVerified
            },
            PeerOprf = ByteString.CopyFrom(oprfResponse),
            Result = OprfRegistrationInitResponse.Types.UpdateResult.Succeeded
        };

        Sender.Tell(Result<OprfRegistrationInitResponse, VerificationFlowFailure>.Ok(response));
        return Task.CompletedTask;
    }

    private async Task HandleCreateMembership(CreateMembershipActorEvent @event)
    {
        Result<MembershipQueryRecord, VerificationFlowFailure> operationResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(@event);
        Sender.Tell(operationResult);
    }

    private async Task HandleSignInMembership(SignInMembershipActorEvent @event)
    {
        IActorRef authContextActor;
        try
        {
            authContextActor = await _authenticationStateManager.Ask<IActorRef>(
                new GetOrCreateAuthContext(@event.ConnectId, @event.MobileNumber),
                TimeSpan.FromSeconds(10));
        }
        catch (Exception ex)
        {
            Sender.Tell(Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Failed to get authentication context actor: {ex.Message}")));
            return;
        }

        AuthResult rateLimitResult;
        try
        {
            rateLimitResult = await authContextActor.Ask<AuthResult>(
                new AttemptAuthentication(@event.MobileNumber),
                TimeSpan.FromSeconds(5));
        }
        catch (Exception ex)
        {
            Sender.Tell(Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Rate limit check failed: {ex.Message}")));
            return;
        }

        if (rateLimitResult is AuthResult.RateLimited rateLimited)
        {
            string messageTemplate = _localizationProvider.Localize(
                VerificationFlowMessageKeys.TooManySigninAttempts,
                @event.CultureName
            );

            int minutesUntilRetry = (int)Math.Ceiling((rateLimited.LockedUntil - DateTime.UtcNow).TotalMinutes);
            string message = string.Format(messageTemplate, minutesUntilRetry);

            Sender.Tell(Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Ok(new OpaqueSignInInitResponse
            {
                Result = OpaqueSignInInitResponse.Types.SignInResult.LoginAttemptExceeded,
                Message = message,
                MinutesUntilRetry = minutesUntilRetry
            }));
            return;
        }

        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(@event);

        Result<OpaqueSignInInitResponse, VerificationFlowFailure> finalResult = persistorResult.Match(
            record =>
            {
                Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> initiateSignInResult =
                    _opaqueProtocolService.InitiateSignIn(
                        @event.OpaqueSignInInitRequest,
                        new MembershipOpaqueQueryRecord(@event.MobileNumber, record.SecureKey, record.MaskingKey));

                if (initiateSignInResult.IsErr)
                {
                    return Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Err(VerificationFlowFailure
                        .InvalidOpaque());
                }

                (OpaqueSignInInitResponse response, byte[] serverMac) = initiateSignInResult.Unwrap();

                _pendingSignIns[@event.ConnectId] = (record.UniqueIdentifier, Guid.NewGuid(), @event.MobileNumber,
                    record.ActivityStatus, record.CreationStatus, DateTime.UtcNow, serverMac);

                return Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Ok(response);
            },
            failure => TranslateSignInFailure(failure, @event.CultureName));

        Sender.Tell(finalResult);
    }

    private async Task HandleSignInComplete(SignInCompleteEvent @event)
    {
        if (!_pendingSignIns.TryGetValue(@event.ConnectId,
                out (Guid MembershipId, Guid MobileNumberId, string MobileNumber, Membership.Types.ActivityStatus
                ActivityStatus, Membership.Types.CreationStatus CreationStatus, DateTime CreatedAt, byte[] ServerMac) membershipInfo))
        {
            Sender.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque("No matching sign-in initiation found for this connection")));
            return;
        }

        Result<OpaqueSignInFinalizeResponse, OpaqueFailure> opaqueResult =
            _opaqueProtocolService.CompleteSignIn(@event.Request, membershipInfo.ServerMac);

        if (opaqueResult.IsErr)
        {
            SecureRemovePendingSignIn(@event.ConnectId);
            Sender.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque(opaqueResult.UnwrapErr().Message)));
            return;
        }

        OpaqueSignInFinalizeResponse finalizeResponse = opaqueResult.Unwrap();

        if (finalizeResponse.Result == OpaqueSignInFinalizeResponse.Types.SignInResult.Succeeded &&
            finalizeResponse.SessionKey != null && !finalizeResponse.SessionKey.IsEmpty)
        {
            try
            {
                Result<Unit, string> storeResult = await _sessionKeyService.StoreSessionKeyAsync(
                    @event.ConnectId, finalizeResponse.SessionKey.ToByteArray());

                if (storeResult.IsErr)
                {
                    SecureRemovePendingSignIn(@event.ConnectId);
                    Sender.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.PersistorAccess($"Failed to store session key: {storeResult.UnwrapErr()}")));
                    return;
                }
            }
            catch (Exception ex)
            {
                SecureRemovePendingSignIn(@event.ConnectId);
                Sender.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess($"Failed to store session key: {ex.Message}")));
                return;
            }
        }

        try
        {
            IActorRef authContextActor = await _authenticationStateManager.Ask<IActorRef>(
                new GetOrCreateAuthContext(@event.ConnectId, membershipInfo.MobileNumber));

            Result<AuthContextTokenResponse, OpaqueFailure> contextResult =
                _opaqueProtocolService.GenerateAuthenticationContext(
                    membershipInfo.MembershipId,
                    membershipInfo.MobileNumberId
                );

            if (contextResult.IsErr)
            {
                SecureRemovePendingSignIn(@event.ConnectId);
                Sender.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.InvalidOpaque(
                        $"Failed to generate authentication context: {contextResult.UnwrapErr().Message}")));
                return;
            }

            AuthContextTokenResponse contextData = contextResult.Unwrap();

            _ = await authContextActor.Ask<AuthContextEstablished>(
                new EstablishContext(contextData.MembershipId, contextData.MobileNumberId, contextData.ContextToken),
                TimeSpan.FromSeconds(10));

            Result<AuthContextQueryResult, VerificationFlowFailure> persistResult =
                await _authContextPersistor.Ask<Result<AuthContextQueryResult, VerificationFlowFailure>>(
                    new CreateAuthContextActorEvent(
                        contextData.ContextToken,
                        contextData.MembershipId,
                        contextData.MobileNumberId,
                        contextData.ExpiresAt
                    ),
                    TimeSpan.FromSeconds(15));

            if (persistResult.IsErr)
            {
            }

            SecureRemovePendingSignIn(@event.ConnectId);

            finalizeResponse.Membership = new Membership
            {
                UniqueIdentifier = ByteString.CopyFrom(membershipInfo.MembershipId.ToByteArray()),
                Status = membershipInfo.ActivityStatus,
                CreationStatus = membershipInfo.CreationStatus
            };

            Sender.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Ok(finalizeResponse));
        }
        catch (Exception ex)
        {
            SecureRemovePendingSignIn(@event.ConnectId);
            Log.Error(ex, "Error during sign-in completion for connectId {ConnectId}", @event.ConnectId);
            Sender.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Authentication context creation failed: {ex.Message}")));
        }
    }

    private void SecureRemovePendingSignIn(uint connectId)
    {
        if (_pendingSignIns.TryGetValue(connectId, out var membershipInfo))
        {
            CryptographicOperations.ZeroMemory(membershipInfo.ServerMac);
            _pendingSignIns.Remove(connectId);
        }
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
                string messageTemplate = _localizationProvider.Localize(
                    VerificationFlowMessageKeys.TooManySigninAttempts,
                    cultureName
                );

                int.TryParse(failure.Message, out int minutesUntilRetry);
                string message = string.Format(messageTemplate, minutesUntilRetry);

                return Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Ok(new OpaqueSignInInitResponse
                {
                    Result = OpaqueSignInInitResponse.Types.SignInResult.LoginAttemptExceeded,
                    Message = message,
                    MinutesUntilRetry = minutesUntilRetry
                });
            }

            default:
                return Result<OpaqueSignInInitResponse, VerificationFlowFailure>
                    .Err(failure);
        }
    }

    private void CleanupExpiredPendingSignIns()
    {
        DateTime cutoffTime = DateTime.UtcNow - PendingSignInTimeout;
        List<uint> expiredConnections = _pendingSignIns
            .Where(kvp => kvp.Value.CreatedAt < cutoffTime)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (uint connectId in expiredConnections)
        {
            SecureRemovePendingSignIn(connectId);
        }

        if (expiredConnections.Count > 0)
        {
            Log.Information("Cleaned up {ExpiredCount} expired pending sign-ins", expiredConnections.Count);
        }
    }
}

internal record CleanupExpiredPendingSignIns;