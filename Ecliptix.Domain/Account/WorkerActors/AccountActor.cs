using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.Domain.Account.ActorEvents;
using Ecliptix.Domain.Account.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Services.Security;
using Ecliptix.Protobuf.Account;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures.Sodium;
using Serilog;
using OprfRegistrationCompleteResponse = Ecliptix.Protobuf.Account.OpaqueRegistrationCompleteResponse;
using OprfRecoverySecretKeyCompleteResponse = Ecliptix.Protobuf.Account.OpaqueRecoverySecretKeyCompleteResponse;
using OprfRecoverySecureKeyInitResponse = Ecliptix.Protobuf.Account.OpaqueRecoverySecureKeyInitResponse;
using OprfRegistrationInitResponse = Ecliptix.Protobuf.Account.OpaqueRegistrationInitResponse;
using ByteString = Google.Protobuf.ByteString;

namespace Ecliptix.Domain.Account.WorkerActors;

public sealed class AccountActor : ReceiveActor
{
    private readonly ILocalizationProvider _localizationProvider;
    private readonly IActorRef _persistor;
    private readonly IOpaqueProtocolService _opaqueProtocolService;
    private readonly IMasterKeyService _masterKeyService;

    private readonly
        Dictionary<uint, (Guid AccountId, Guid MobileNumberId, string MobileNumber,
            Protobuf.Account.Account.Types.ActivityStatus ActivityStatus, Protobuf.Account.Account.Types.CreationStatus
            CreationStatus, DateTime CreatedAt, byte[] ServerMac)> _pendingSignIns = new();

    private readonly Dictionary<Guid, byte[]> _pendingMaskingKeys = new();
    private readonly Dictionary<Guid, SodiumSecureMemoryHandle> _pendingSessionKeys = new();
    private readonly Dictionary<Guid, DateTime> _pendingRecoveryTimestamps = new();

    private static readonly TimeSpan PendingSignInTimeout = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan PendingPasswordRecoveryTimeout = TimeSpan.FromMinutes(10);
    private ICancelable? _cleanupTimer;

    public AccountActor(IActorRef persistor,
        IOpaqueProtocolService opaqueProtocolService,
        ILocalizationProvider localizationProvider,
        IMasterKeyService masterKeyService)
    {
        _persistor = persistor;
        _opaqueProtocolService = opaqueProtocolService;
        _localizationProvider = localizationProvider;
        _masterKeyService = masterKeyService;

        Become(Ready);
    }

    public static Props Build(IActorRef persistor,
        IOpaqueProtocolService opaqueProtocolService,
        ILocalizationProvider localizationProvider,
        IMasterKeyService masterKeyService)
    {
        return Props.Create(() => new AccountActor(persistor, opaqueProtocolService,
            localizationProvider, masterKeyService));
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

        Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
            TimeSpan.FromMinutes(2),
            TimeSpan.FromMinutes(2),
            Self,
            new CleanupExpiredPasswordRecovery(),
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

        foreach (SodiumSecureMemoryHandle sessionKeyHandle in _pendingSessionKeys.Values)
        {
            sessionKeyHandle?.Dispose();
        }
        _pendingSessionKeys.Clear();

        _pendingRecoveryTimestamps.Clear();

        base.PostStop();
    }

    private void Ready()
    {
        ReceiveAsync<SignInCompleteEvent>(HandleSignInComplete);
        Receive<CleanupExpiredPendingSignIns>(_ => CleanupExpiredPendingSignIns());
        Receive<CleanupExpiredPasswordRecovery>(_ => CleanupExpiredPasswordRecovery());
        ReceiveAsync<GenerateAccountOprfRegistrationRequestEvent>(HandleGenerateAccountOprfRegistrationRecord);
        ReceiveAsync<CreateAccountActorEvent>(HandleCreateAccount);
        ReceiveAsync<SignInAccountActorEvent>(HandleSignInAccount);
        ReceiveAsync<CompleteRegistrationRecordActorEvent>(HandleCompleteRegistrationRecord);
        ReceiveAsync<OprfInitRecoverySecureKeyEvent>(HandleInitRecoveryRequestEvent);
        ReceiveAsync<OprfCompleteRecoverySecureKeyEvent>(HandleCompleteRecoverySecureKeyEvent);
        ReceiveAsync<GetAccountByVerificationFlowEvent>(HandleGetAccountByVerificationFlow);
    }

    private async Task HandleCompleteRegistrationRecord(CompleteRegistrationRecordActorEvent @event)
    {
        if (!_pendingMaskingKeys.TryGetValue(@event.AccountIdentifier, out byte[]? maskingKey))
        {
            Sender.Tell(Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque("No masking key found for account during registration completion")));
            return;
        }

        UpdateAccountSecureKeyEvent updateEvent = new(@event.AccountIdentifier, @event.PeerRegistrationRecord, maskingKey);

        Log.Information("[REGISTRATION-COMPLETE] Updating OPAQUE credentials in database for account {AccountId}",
            @event.AccountIdentifier);

        Result<AccountQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<AccountQueryRecord, VerificationFlowFailure>>(updateEvent);

        if (persistorResult.IsErr)
        {
            _pendingMaskingKeys.Remove(@event.AccountIdentifier);
            Sender.Tell(Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Err(persistorResult.UnwrapErr()));
            return;
        }

        Log.Information("[REGISTRATION-COMPLETE] OPAQUE credentials successfully stored in database for account {AccountId}",
            @event.AccountIdentifier);

        _pendingMaskingKeys.Remove(@event.AccountIdentifier);

        Sender.Tell(Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Ok(
            new OprfRegistrationCompleteResponse
            {
                Result = OprfRegistrationCompleteResponse.Types.RegistrationResult.Succeeded,
                Message = "Registration completed successfully.",
                SessionKey = ByteString.Empty
            }));
    }

    private async Task HandleCompleteRecoverySecureKeyEvent(OprfCompleteRecoverySecureKeyEvent @event)
    {
        if (!_pendingRecoveryTimestamps.TryGetValue(@event.AccountIdentifier, out DateTime initTimestamp))
        {
            Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque("No password recovery session found. Please restart the password recovery process.")));
            return;
        }

        TimeSpan elapsed = DateTime.UtcNow - initTimestamp;
        if (elapsed > PendingPasswordRecoveryTimeout)
        {
            Log.Warning("Password recovery timeout exceeded for account {AccountId}. Elapsed: {Elapsed}, Max: {Max}",
                @event.AccountIdentifier, elapsed, PendingPasswordRecoveryTimeout);
            CleanupPasswordRecoveryState(@event.AccountIdentifier);
            Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic($"Password recovery session expired. Please restart the password recovery process.")));
            return;
        }

        if (!_pendingMaskingKeys.TryGetValue(@event.AccountIdentifier, out byte[]? maskingKey))
        {
            Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque("No masking key found for account during recovery completion")));
            return;
        }

        if (!_pendingSessionKeys.TryGetValue(@event.AccountIdentifier, out SodiumSecureMemoryHandle? sessionKeyHandle))
        {
            _pendingMaskingKeys.Remove(@event.AccountIdentifier);
            Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque("No session key found for account during recovery completion")));
            return;
        }

        if (sessionKeyHandle.IsInvalid)
        {
            _pendingMaskingKeys.Remove(@event.AccountIdentifier);
            _pendingSessionKeys.Remove(@event.AccountIdentifier);
            Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque("Session key handle is invalid")));
            return;
        }

        try
        {
            Result<dynamic, FailureBase> regenerateResult =
                await _masterKeyService.RegenerateMasterKeySharesAsync(
                    sessionKeyHandle, @event.AccountIdentifier);

            if (regenerateResult.IsErr)
            {
                Log.Error("CRITICAL: Failed to regenerate master key shares for account {AccountId}: {Error}. Password reset aborted.",
                    @event.AccountIdentifier, regenerateResult.UnwrapErr().Message);
                _pendingMaskingKeys.Remove(@event.AccountIdentifier);
                sessionKeyHandle?.Dispose();
                _pendingSessionKeys.Remove(@event.AccountIdentifier);
                Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Generic("Failed to regenerate encryption keys. Password reset aborted. Please try again.")));
                return;
            }

            Log.Information("Master key shares regenerated successfully for account {AccountId}",
                @event.AccountIdentifier);
        }
        finally
        {
            sessionKeyHandle?.Dispose();
            _pendingSessionKeys.Remove(@event.AccountIdentifier);
        }

        UpdateAccountSecureKeyEvent updateEvent = new(@event.AccountIdentifier, @event.PeerRecoveryRecord, maskingKey);

        Log.Information("[PASSWORD-RECOVERY-COMPLETE] Updating OPAQUE credentials in database for account {AccountId}",
            @event.AccountIdentifier);

        Result<AccountQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<AccountQueryRecord, VerificationFlowFailure>>(updateEvent);

        if (persistorResult.IsErr)
        {
            _pendingMaskingKeys.Remove(@event.AccountIdentifier);
            Log.Error("CRITICAL: Master keys regenerated but password update failed for account {AccountId}: {Error}. User may be locked out!",
                @event.AccountIdentifier, persistorResult.UnwrapErr().Message);
            Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(persistorResult.UnwrapErr()));
            return;
        }

        Log.Information("[PASSWORD-RECOVERY-COMPLETE] OPAQUE credentials successfully updated in database for account {AccountId}",
            @event.AccountIdentifier);

        _pendingMaskingKeys.Remove(@event.AccountIdentifier);
        _pendingRecoveryTimestamps.Remove(@event.AccountIdentifier);

        Result<Unit, VerificationFlowFailure> expireResult =
            await _persistor.Ask<Result<Unit, VerificationFlowFailure>>(
                new ExpirePasswordRecoveryFlowsEvent(@event.AccountIdentifier));

        if (expireResult.IsErr)
        {
            Log.Warning("Failed to expire password recovery flows for account {AccountId}: {Error}",
                @event.AccountIdentifier, expireResult.UnwrapErr().Message);
        }

        Sender.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Ok(
            new OprfRecoverySecretKeyCompleteResponse
            {
                Message = "Recovery secret key completed successfully."
            }));
    }

    private async Task HandleInitRecoveryRequestEvent(OprfInitRecoverySecureKeyEvent @event)
    {
        Result<PasswordRecoveryFlowValidation, VerificationFlowFailure> flowValidation =
            await _persistor.Ask<Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>>(
                new ValidatePasswordRecoveryFlowEvent(@event.AccountIdentifier));

        if (flowValidation.IsErr)
        {
            Sender.Tell(Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>.Err(flowValidation.UnwrapErr()));
            return;
        }

        PasswordRecoveryFlowValidation validation = flowValidation.Unwrap();
        if (!validation.IsValid)
        {
            string errorMessage = _localizationProvider.Localize(
                VerificationFlowMessageKeys.PasswordRecoveryOtpRequired,
                @event.CultureName);

            Sender.Tell(Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Unauthorized(errorMessage)));
            return;
        }

        if (_pendingRecoveryTimestamps.TryGetValue(@event.AccountIdentifier, out DateTime existingTimestamp))
        {
            TimeSpan elapsed = DateTime.UtcNow - existingTimestamp;
            if (elapsed < PendingPasswordRecoveryTimeout)
            {
                int remainingSeconds = (int)(PendingPasswordRecoveryTimeout - elapsed).TotalSeconds;
                Log.Warning("Password recovery already in progress for account {AccountId}. Time remaining: {Seconds}s",
                    @event.AccountIdentifier, remainingSeconds);
                Sender.Tell(Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Generic($"A password reset is already in progress. Please wait {remainingSeconds} seconds before trying again.")));
                return;
            }
            else
            {
                Log.Information("Previous password recovery attempt expired for account {AccountId}. Cleaning up and allowing new attempt.",
                    @event.AccountIdentifier);
                CleanupPasswordRecoveryState(@event.AccountIdentifier);
            }
        }

        (byte[] oprfResponse, byte[] maskingKey, byte[] sessionKey) = _opaqueProtocolService.ProcessOprfRequestWithSessionKey(@event.OprfRequest);

        string sessionKeyFingerprint = Convert.ToHexString(SHA256.HashData(sessionKey))[..16];
        Log.Information("[PASSWORD-RECOVERY-INIT-EXPORTKEY] OPAQUE export_key derived during password recovery INIT. AccountId: {AccountId}, ExportKeyFingerprint: {ExportKeyFingerprint}",
            @event.AccountIdentifier, sessionKeyFingerprint);

        try
        {
            Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult =
                SodiumSecureMemoryHandle.Allocate(sessionKey.Length);

            if (allocateResult.IsErr)
            {
                Log.Error("Failed to allocate secure memory for session key: {Error}",
                    allocateResult.UnwrapErr().Message);
                CryptographicOperations.ZeroMemory(maskingKey);
                CryptographicOperations.ZeroMemory(sessionKey);
                Sender.Tell(Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Generic("Failed to process session key securely")));
                return;
            }

            SodiumSecureMemoryHandle sessionKeyHandle = allocateResult.Unwrap();
            Result<Unit, SodiumFailure> writeResult = sessionKeyHandle.Write(sessionKey);

            if (writeResult.IsErr)
            {
                Log.Error("Failed to write session key to secure memory: {Error}",
                    writeResult.UnwrapErr().Message);
                sessionKeyHandle.Dispose();
                CryptographicOperations.ZeroMemory(maskingKey);
                CryptographicOperations.ZeroMemory(sessionKey);
                Sender.Tell(Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Generic("Failed to process session key securely")));
                return;
            }

            _pendingMaskingKeys[@event.AccountIdentifier] = maskingKey;
            _pendingSessionKeys[@event.AccountIdentifier] = sessionKeyHandle;
            _pendingRecoveryTimestamps[@event.AccountIdentifier] = DateTime.UtcNow;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionKey);
        }

        OprfRecoverySecureKeyInitResponse response = new()
        {
            Account = new Protobuf.Account.Account()
            {
                UniqueIdentifier = Helpers.GuidToByteString(@event.AccountIdentifier),
                Status = Protobuf.Account.Account.Types.ActivityStatus.Active,
                CreationStatus = Protobuf.Account.Account.Types.CreationStatus.SecureKeySet
            },
            PeerOprf = ByteString.CopyFrom(oprfResponse),
            Result = OprfRecoverySecureKeyInitResponse.Types.RecoveryResult.Succeeded
        };

        Log.Information("[PASSWORD-RECOVERY-INIT] OPRF generated for account {AccountId}. Credentials stored in pending state (NOT persisted to database yet).",
            @event.AccountIdentifier);

        Sender.Tell(Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>.Ok(response));
    }

    private Task HandleGenerateAccountOprfRegistrationRecord(
        GenerateAccountOprfRegistrationRequestEvent @event)
    {
        (byte[] oprfResponse, byte[] maskingKey) = _opaqueProtocolService.ProcessOprfRequest(@event.OprfRequest);

        _pendingMaskingKeys[@event.AccountIdentifier] = maskingKey;

        OprfRegistrationInitResponse response = new()
        {
            Account = new Protobuf.Account.Account
            {
                UniqueIdentifier = Helpers.GuidToByteString(@event.AccountIdentifier),
                Status = Protobuf.Account.Account.Types.ActivityStatus.Inactive,
                CreationStatus = Protobuf.Account.Account.Types.CreationStatus.OtpVerified
            },
            PeerOprf = ByteString.CopyFrom(oprfResponse),
            Result = OprfRegistrationInitResponse.Types.UpdateResult.Succeeded
        };

        Sender.Tell(Result<OprfRegistrationInitResponse, VerificationFlowFailure>.Ok(response));
        return Task.CompletedTask;
    }

    private async Task HandleCreateAccount(CreateAccountActorEvent @event)
    {
        Result<AccountQueryRecord, VerificationFlowFailure> operationResult =
            await _persistor.Ask<Result<AccountQueryRecord, VerificationFlowFailure>>(@event);
        Sender.Tell(operationResult);
    }

    private async Task HandleGetAccountByVerificationFlow(GetAccountByVerificationFlowEvent @event)
    {
        Result<AccountQueryRecord, VerificationFlowFailure> operationResult =
            await _persistor.Ask<Result<AccountQueryRecord, VerificationFlowFailure>>(@event);
        Sender.Tell(operationResult);
    }

    private async Task HandleSignInAccount(SignInAccountActorEvent @event)
    {
        Result<AccountQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<AccountQueryRecord, VerificationFlowFailure>>(@event);

        Result<OpaqueSignInInitResponse, VerificationFlowFailure> finalResult = persistorResult.Match(
            record =>
            {
                Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> initiateSignInResult =
                    _opaqueProtocolService.InitiateSignIn(
                        @event.OpaqueSignInInitRequest,
                        new AccountOpaqueQueryRecord(@event.MobileNumber, record.SecureKey, record.MaskingKey));

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
                out (Guid AccountId, Guid MobileNumberId, string MobileNumber, Protobuf.Account.Account.Types.ActivityStatus
                ActivityStatus, Protobuf.Account.Account.Types.CreationStatus CreationStatus, DateTime CreatedAt, byte[] ServerMac) accountInfo))
        {
            Sender.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque("No matching sign-in initiation found for this connection")));
            return;
        }

        Result<(SodiumSecureMemoryHandle SessionKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure> opaqueResult =
            _opaqueProtocolService.CompleteSignIn(@event.Request, accountInfo.ServerMac);

        if (opaqueResult.IsErr)
        {
            SecureRemovePendingSignIn(@event.ConnectId);
            Sender.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque(opaqueResult.UnwrapErr().Message)));
            return;
        }

        (SodiumSecureMemoryHandle sessionKeyHandle, OpaqueSignInFinalizeResponse finalizeResponse) = opaqueResult.Unwrap();

        Result<byte[], SodiumFailure> sessionKeyBytesResult = sessionKeyHandle.ReadBytes(sessionKeyHandle.Length);
        if (sessionKeyBytesResult.IsOk)
        {
            byte[] sessionKeyBytes = sessionKeyBytesResult.Unwrap();
            string sessionKeyFingerprint = Convert.ToHexString(SHA256.HashData(sessionKeyBytes))[..16];
            Log.Information("[SERVER-OPAQUE-EXPORTKEY] OPAQUE export_key (session key) derived. AccountId: {AccountId}, SessionKeyFingerprint: {SessionKeyFingerprint}",
                accountInfo.AccountId, sessionKeyFingerprint);
            CryptographicOperations.ZeroMemory(sessionKeyBytes);
        }

        if (finalizeResponse.Result == OpaqueSignInFinalizeResponse.Types.SignInResult.Succeeded &&
            !sessionKeyHandle.IsInvalid)
        {
            await EnsureMasterKeySharesExist(sessionKeyHandle, accountInfo.AccountId);
        }

        SecureRemovePendingSignIn(@event.ConnectId);

        finalizeResponse.Account = new Protobuf.Account.Account
        {
            UniqueIdentifier = Helpers.GuidToByteString(accountInfo.AccountId),
            Status = accountInfo.ActivityStatus,
            CreationStatus = accountInfo.CreationStatus
        };

        Sender.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Ok(finalizeResponse));
    }

    private void SecureRemovePendingSignIn(uint connectId)
    {
        if (_pendingSignIns.TryGetValue(connectId,
                out (Guid AccountId, Guid MobileNumberId, string MobileNumber, Protobuf.Account.Account.Types.ActivityStatus
                ActivityStatus, Protobuf.Account.Account.Types.CreationStatus CreationStatus, DateTime CreatedAt, byte[] ServerMac)
                accountInfo))
        {
            CryptographicOperations.ZeroMemory(accountInfo.ServerMac);
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
    }

    private void CleanupExpiredPasswordRecovery()
    {
        DateTime cutoffTime = DateTime.UtcNow - PendingPasswordRecoveryTimeout;
        List<Guid> expiredRecoveries = _pendingRecoveryTimestamps
            .Where(kvp => kvp.Value < cutoffTime)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (Guid accountId in expiredRecoveries)
        {
            Log.Information("Cleaning up expired password recovery attempt for account {AccountId}", accountId);
            CleanupPasswordRecoveryState(accountId);
        }
    }

    private void CleanupPasswordRecoveryState(Guid accountId)
    {
        if (_pendingMaskingKeys.TryGetValue(accountId, out byte[]? maskingKey))
        {
            CryptographicOperations.ZeroMemory(maskingKey);
            _pendingMaskingKeys.Remove(accountId);
        }

        if (_pendingSessionKeys.TryGetValue(accountId, out SodiumSecureMemoryHandle? sessionKeyHandle))
        {
            sessionKeyHandle?.Dispose();
            _pendingSessionKeys.Remove(accountId);
        }

        _pendingRecoveryTimestamps.Remove(accountId);
    }

    private async Task EnsureMasterKeySharesExist(SodiumSecureMemoryHandle sessionKeyHandle, Guid accountId)
    {
        Result<bool, FailureBase> checkResult = await _masterKeyService.CheckSharesExistAsync(accountId);

        if (checkResult.IsErr || !checkResult.Unwrap())
        {
            Result<dynamic, FailureBase> createResult = await _masterKeyService.DeriveMasterKeyAndSplitAsync(sessionKeyHandle, accountId);

            if (createResult.IsErr)
            {
                Log.Error(
                    "[MASTER-KEY-CREATE] Failed to create master key shares for account {AccountId}: {Error}",
                    accountId,
                    createResult.UnwrapErr().Message);
            }
            else
            {
                Log.Information(
                    "[MASTER-KEY-CREATE] Successfully created master key shares for account {AccountId} on first login",
                    accountId);
            }
            return;
        }

        Result<string, FailureBase> validationResult = await _masterKeyService.ValidateMasterKeySharesAsync(sessionKeyHandle, accountId);

        if (validationResult.IsErr)
        {
            Log.Error("[MASTER-KEY-VALIDATE] Failed to validate master key shares for account {AccountId}: {Error}",
                accountId, validationResult.UnwrapErr().Message);
            return;
        }

        string validationStatus = validationResult.Unwrap();

        if (validationStatus == "mismatch")
        {
            Log.Warning("[MASTER-KEY-MISMATCH] Export key mismatch detected for account {AccountId}. OPAQUE credentials changed since last login. Regenerating master key shares...",
                accountId);

            Result<dynamic, FailureBase> regenResult = await _masterKeyService.RegenerateMasterKeySharesAsync(sessionKeyHandle, accountId);

            if (regenResult.IsErr)
            {
                Log.Error(
                    "[MASTER-KEY-REGEN] CRITICAL: Failed to regenerate master key shares for account {AccountId}: {Error}",
                    accountId,
                    regenResult.UnwrapErr().Message);
            }
            else
            {
                Log.Information(
                    "[MASTER-KEY-REGEN] Successfully regenerated master key shares for account {AccountId} after export key change",
                    accountId);
            }
        }
        else
        {
            Log.Information("[MASTER-KEY-VALID] Master key shares are valid for account {AccountId}. No regeneration needed.",
                accountId);
        }
    }
}

public record UpdateAccountSecureKeyEvent(Guid AccountIdentifier, byte[] SecureKey, byte[] MaskingKey);

public record GenerateAccountOprfRegistrationRequestEvent(Guid AccountIdentifier, byte[] OprfRequest);

public record CompleteRegistrationRecordActorEvent(Guid AccountIdentifier, byte[] PeerRegistrationRecord, uint ConnectId);

public record OprfInitRecoverySecureKeyEvent(Guid AccountIdentifier, byte[] OprfRequest, string CultureName);

public record OprfCompleteRecoverySecureKeyEvent(Guid AccountIdentifier, byte[] PeerRecoveryRecord);

public record SignInCompleteEvent(uint ConnectId, OpaqueSignInFinalizeRequest Request);

internal record CleanupExpiredPendingSignIns;

internal record CleanupExpiredPasswordRecovery;