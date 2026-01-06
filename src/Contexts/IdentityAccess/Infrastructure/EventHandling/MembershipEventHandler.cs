using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Account;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.AccountProfile;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Logout;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Membership;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Memberships.MobileNumberValidation;
using Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.IdentityAccess.Domain.Services.Security;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Protobuf.Account;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel.Failures.Sodium;
using Ecliptix.SharedKernel.Grpc;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Ecliptix.SharedKernel.Grpc.Utilities.CipherPayloadHandler;
using Ecliptix.SharedKernel.KeyDerivation;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.Options;
using Serilog;
using OprfRecoverySecretKeyCompleteRequest = Ecliptix.Protobuf.Membership.OpaqueRecoverySecretKeyCompleteRequest;
using OprfRecoverySecretKeyCompleteResponse = Ecliptix.Protobuf.Membership.OpaqueRecoverySecretKeyCompleteResponse;
using OprfRecoverySecureKeyInitRequest = Ecliptix.Protobuf.Membership.OpaqueRecoverySecureKeyInitRequest;
using OprfRecoverySecureKeyInitResponse = Ecliptix.Protobuf.Membership.OpaqueRecoverySecureKeyInitResponse;
using OprfRegistrationCompleteRequest = Ecliptix.Protobuf.Membership.OpaqueRegistrationCompleteRequest;
using OprfRegistrationCompleteResponse = Ecliptix.Protobuf.Membership.OpaqueRegistrationCompleteResponse;
using OprfRegistrationInitRequest = Ecliptix.Protobuf.Membership.OpaqueRegistrationInitRequest;
using OprfRegistrationInitResponse = Ecliptix.Protobuf.Membership.OpaqueRegistrationInitResponse;
using Status = Grpc.Core.Status;

namespace Ecliptix.IdentityAccess.Infrastructure.EventHandling;

/// <summary>
/// Internal command handler for membership flows (used via gateway).
/// </summary>
public sealed class MembershipEventHandler
{
    private readonly GrpcSecurityService _service;
    private readonly IActorRef _membershipActor;
    private readonly IActorRef _accountPersistor;
    private readonly IActorRef _logoutAuditPersistor;
    private readonly IActorRef _protocolActor;
    private readonly IMobileNumberValidator _phoneNumberValidator;
    private readonly IMasterKeyService _masterKeyService;
    private readonly ActorSystem _actorSystem;
    private readonly string _cultureName = CultureInfo.CurrentCulture.Name;
    private readonly SecurityConfiguration _securityConfig;

    public MembershipEventHandler(
        IEcliptixActorRegistry actorRegistry,
        IMobileNumberValidator phoneNumberValidator,
        IGrpcCipherService grpcCipherService,
        ActorSystem actorSystem,
        IMasterKeyService masterKeyService,
        IOptions<SecurityConfiguration> securityConfig)
    {
        _service = new GrpcSecurityService(grpcCipherService, securityConfig);
        _membershipActor = actorRegistry.Get(ActorIds.MembershipActor);
        _accountPersistor = actorRegistry.Get(ActorIds.AccountPersistorActor);
        _logoutAuditPersistor = actorRegistry.Get(ActorIds.LogoutAuditPersistorActor);
        _protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);
        _phoneNumberValidator = phoneNumberValidator;
        _masterKeyService = masterKeyService;
        _actorSystem = actorSystem;
        _securityConfig = securityConfig.Value;
    }

    public async Task<SecureEnvelope> OpaqueSignInInitRequest(SecureEnvelope request,
        ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<OpaqueSignInInitRequest, OpaqueSignInInitResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                Result<MobileNumberValidationResult, VerificationFlowFailure> phoneNumberValidationResult =
                    _phoneNumberValidator.ValidateMobileNumber(message.MobileNumber, _cultureName);

                if (phoneNumberValidationResult.IsErr)
                {
                    VerificationFlowFailure verificationFlowFailure = phoneNumberValidationResult.UnwrapErr();
                    if (verificationFlowFailure.IsUserFacing)
                    {
                        return Result<OpaqueSignInInitResponse, FailureBase>.Ok(new OpaqueSignInInitResponse
                        {
                            Result = OpaqueSignInInitResponse.Types.SignInResult.InvalidCredentials,
                            Message = verificationFlowFailure.Message
                        });
                    }

                    return Result<OpaqueSignInInitResponse, FailureBase>.Err(verificationFlowFailure);
                }

                MobileNumberValidationResult phoneNumberResult = phoneNumberValidationResult.Unwrap();
                if (!phoneNumberResult.IsValid)
                {
                    return Result<OpaqueSignInInitResponse, FailureBase>.Ok(new OpaqueSignInInitResponse
                    {
                        Result = OpaqueSignInInitResponse.Types.SignInResult.InvalidCredentials,
                        Message = phoneNumberResult.LocalizedMessage.Value!
                    });
                }

                Guid deviceId = DeviceIdResolver.ResolveDeviceIdFromContext(context);

                SignInMembershipActorEvent signInEvent = new(
                    connectId,
                    phoneNumberResult.ParsedMobileNumberE164.Value!,
                    deviceId,
                    message,
                    _cultureName,
                    cancellationToken);

                Task<Result<OpaqueSignInInitResponse, MembershipFailure>> initSignInTask =
                    _membershipActor.Ask<Result<OpaqueSignInInitResponse, MembershipFailure>>(
                        signInEvent,
                        TimeoutConfiguration.Actor.AskTimeout);

                Result<OpaqueSignInInitResponse, MembershipFailure> initSignInResult =
                    await initSignInTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                return initSignInResult.Match(
                    ok: Result<OpaqueSignInInitResponse, FailureBase>.Ok,
                    err: Result<OpaqueSignInInitResponse, FailureBase>.Err
                );
            });
    }

    public async Task<SecureEnvelope> OpaqueSignInCompleteRequest(SecureEnvelope request,
        ServerCallContext context)
    {
        return await _service
            .ExecuteEncryptedOperationAsync<OpaqueSignInFinalizeRequest, OpaqueSignInFinalizeResponse>(
                request, context,
                async (message, connectId, _, cancellationToken) =>
                {
                    Task<Result<OpaqueSignInFinalizeResponse, MembershipFailure>> finalizeSignInTask =
                        _membershipActor.Ask<Result<OpaqueSignInFinalizeResponse, MembershipFailure>>(
                            new SignInCompleteEvent(connectId, message),
                            TimeoutConfiguration.Actor.AskTimeout);

                    Result<OpaqueSignInFinalizeResponse, MembershipFailure> finalizeSignInResult =
                        await finalizeSignInTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                    return finalizeSignInResult.Match(
                        ok: Result<OpaqueSignInFinalizeResponse, FailureBase>.Ok,
                        err: Result<OpaqueSignInFinalizeResponse, FailureBase>.Err
                    );
                });
    }

    public async Task<SecureEnvelope> OpaqueRegistrationCompleteRequest(SecureEnvelope request,
        ServerCallContext context)
    {
        return await _service
            .ExecuteEncryptedOperationAsync<OprfRegistrationCompleteRequest, OprfRegistrationCompleteResponse>(request,
                context,
                async (message, _, _, cancellationToken) =>
                {
                    byte[] peerRecord = Helpers.ReadMemoryToRetrieveBytes(message.PeerRegistrationRecord.Memory);

                    try
                    {
                        CompleteRegistrationRecordActorEvent @event = new(
                            Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                            peerRecord,
                            cancellationToken);

                        Task<Result<OprfRegistrationCompleteResponse, AccountFailure>> completeRegistrationRecordTask =
                            _membershipActor.Ask<Result<OprfRegistrationCompleteResponse, AccountFailure>>(
                                @event,
                                TimeoutConfiguration.Actor.AskTimeout);

                        Result<OprfRegistrationCompleteResponse, AccountFailure> completeRegistrationRecordResult =
                            await completeRegistrationRecordTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                        return completeRegistrationRecordResult.Match(
                            ok: Result<OprfRegistrationCompleteResponse, FailureBase>.Ok,
                            err: Result<OprfRegistrationCompleteResponse, FailureBase>.Err
                        );
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(peerRecord);
                    }
                });
    }

    public async Task<SecureEnvelope> OpaqueRecoverySecretKeyCompleteRequest(SecureEnvelope request,
        ServerCallContext context)
    {
        return await _service
            .ExecuteEncryptedOperationAsync<OprfRecoverySecretKeyCompleteRequest,
                OprfRecoverySecretKeyCompleteResponse>(
                request, context,
                async (message, _, _, cancellationToken) =>
                {
                    byte[] peerRecovery = Helpers.ReadMemoryToRetrieveBytes(message.PeerRecoveryRecord.Memory);

                    try
                    {
                        OprfCompleteRecoverySecureKeyEvent @event = new(
                            Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                            peerRecovery,
                            cancellationToken);

                        Task<Result<OprfRecoverySecretKeyCompleteResponse, SecretKeyRecoveryFailure>>
                            completeRecoverySecretKeyTask =
                                _membershipActor
                                    .Ask<Result<OprfRecoverySecretKeyCompleteResponse, SecretKeyRecoveryFailure>>(
                                        @event,
                                        TimeoutConfiguration.Actor.AskTimeout);

                        Result<OprfRecoverySecretKeyCompleteResponse, SecretKeyRecoveryFailure>
                            completeRecoverySecretKeyResult =
                                await completeRecoverySecretKeyTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                        return completeRecoverySecretKeyResult.Match(
                            ok: Result<OprfRecoverySecretKeyCompleteResponse, FailureBase>.Ok,
                            err: Result<OprfRecoverySecretKeyCompleteResponse, FailureBase>.Err
                        );
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(peerRecovery);
                    }
                });
    }

    public async Task<SecureEnvelope> OpaqueRegistrationInitRequest(SecureEnvelope request,
        ServerCallContext context)
    {
        return await _service
            .ExecuteEncryptedOperationAsync<OprfRegistrationInitRequest, OprfRegistrationInitResponse>(
                request, context,
                async (message, _, _, cancellationToken) =>
                {
                    byte[] peerOprf = Helpers.ReadMemoryToRetrieveBytes(message.PeerOprf.Memory);
                    try
                    {
                        GenerateMembershipOprfRegistrationRequestEvent @event = new(
                            Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                            peerOprf,
                            cancellationToken);

                        Task<Result<OprfRegistrationInitResponse, AccountFailure>> updateOperationTask =
                            _membershipActor.Ask<Result<OprfRegistrationInitResponse, AccountFailure>>(
                                @event,
                                TimeoutConfiguration.Actor.AskTimeout);

                        Result<OprfRegistrationInitResponse, AccountFailure> updateOperationResult =
                            await updateOperationTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                        return updateOperationResult.Match(
                            ok: Result<OprfRegistrationInitResponse, FailureBase>.Ok,
                            err: Result<OprfRegistrationInitResponse, FailureBase>.Err
                        );
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(peerOprf);
                    }
                });
    }

    public async Task<SecureEnvelope> OpaqueRecoverySecretKeyInitRequest(SecureEnvelope request,
        ServerCallContext context)
    {
        return await _service
            .ExecuteEncryptedOperationAsync<OprfRecoverySecureKeyInitRequest, OprfRecoverySecureKeyInitResponse>(
                request, context,
                async (message, _, _, cancellationToken) =>
                {
                    byte[] peerOprf = Helpers.ReadMemoryToRetrieveBytes(message.PeerOprf.Memory);
                    try
                    {
                        OprfInitRecoverySecureKeyEvent @event = new(
                            Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                            peerOprf,
                            _cultureName,
                            cancellationToken);

                        Task<Result<OprfRecoverySecureKeyInitResponse, SecretKeyRecoveryFailure>> recoveryInitTask =
                            _membershipActor.Ask<Result<OprfRecoverySecureKeyInitResponse, SecretKeyRecoveryFailure>>(
                                @event,
                                TimeoutConfiguration.Actor.AskTimeout);

                        Result<OprfRecoverySecureKeyInitResponse, SecretKeyRecoveryFailure> result =
                            await recoveryInitTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                        return result.Match(
                            ok: Result<OprfRecoverySecureKeyInitResponse, FailureBase>.Ok,
                            err: Result<OprfRecoverySecureKeyInitResponse, FailureBase>.Err
                        );
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(peerOprf);
                    }
                }
            );
    }

    private async Task<Result<Guid, FailureBase>> ResolveAccountIdAsync(
        Guid membershipId,
        ByteString? accountIdentifier,
        CancellationToken cancellationToken)
    {
        if (accountIdentifier != null && accountIdentifier.Length > 0)
        {
            return Result<Guid, FailureBase>.Ok(Helpers.FromByteStringToGuid(accountIdentifier));
        }

        Task<Result<Option<Guid>, AccountFailure>> accountTask =
            _accountPersistor.Ask<Result<Option<Guid>, AccountFailure>>(
                new GetDefaultAccountIdEvent(membershipId, cancellationToken),
                TimeoutConfiguration.Actor.AskTimeout);

        Result<Option<Guid>, AccountFailure> accountResult =
            await accountTask.WaitAsync(cancellationToken).ConfigureAwait(false);

        if (accountResult.IsErr)
        {
            return Result<Guid, FailureBase>.Err(accountResult.UnwrapErr());
        }

        Option<Guid> accountOpt = accountResult.Unwrap();
        if (!accountOpt.IsSome)
        {
            return Result<Guid, FailureBase>.Err(MasterKeyFailure.DefaultAccountNotFound());
        }

        return Result<Guid, FailureBase>.Ok(accountOpt.Value);
    }

    private async Task<Result<Unit, FailureBase>> ValidateLogoutHmacAsync(
        LogoutRequest message,
        Guid accountId)
    {
        if (message.HmacProof == null || message.HmacProof.IsEmpty)
        {
            Log.Warning("[LOGOUT-HMAC] Missing HMAC proof for AccountId: {AccountId}", accountId);
            return Result<Unit, FailureBase>.Err(
                MembershipFailure.ValidationFailed("Missing HMAC authentication proof"));
        }

        SodiumSecureMemoryHandle? masterKeyHandle = null;
        byte[]? logoutHmacKey = null;

        try
        {
            Result<dynamic, FailureBase> handleResult =
                await _masterKeyService.GetMasterKeyHandleAsync(accountId);

            if (handleResult.IsErr)
            {
                Log.Error("[LOGOUT-HMAC] Failed to retrieve master key handle for AccountId: {AccountId}",
                    accountId);
                return Result<Unit, FailureBase>.Err(handleResult.UnwrapErr());
            }

            masterKeyHandle = (SodiumSecureMemoryHandle)handleResult.Unwrap();

            Result<byte[], SodiumFailure> hmacKeyResult =
                LogoutKeyDerivation.DeriveLogoutHmacKey(masterKeyHandle);

            if (hmacKeyResult.IsErr)
            {
                Log.Error("[LOGOUT-HMAC] Failed to derive logout HMAC key for AccountId: {AccountId}",
                    accountId);
                return Result<Unit, FailureBase>.Err(
                    MembershipFailure.ValidationFailed(
                        $"HMAC key derivation failed: {hmacKeyResult.UnwrapErr().Message}"));
            }

            logoutHmacKey = hmacKeyResult.Unwrap();

            string canonical = BuildCanonicalLogoutRequest(message);
            int maxByteCount = System.Text.Encoding.UTF8.GetMaxByteCount(canonical.Length);
            byte[] canonicalBytes = ArrayPool<byte>.Shared.Rent(maxByteCount);

            try
            {
                int actualByteCount = System.Text.Encoding.UTF8.GetBytes(canonical, canonicalBytes);
                byte[] canonicalData = canonicalBytes.AsSpan(0, actualByteCount).ToArray();

                byte[] clientHmac = message.HmacProof.ToByteArray();
                bool isValid = LogoutKeyDerivation.VerifyHmac(logoutHmacKey, canonicalData, clientHmac);

                if (!isValid)
                {
                    Log.Warning("[LOGOUT-HMAC] HMAC verification failed for AccountId: {AccountId}",
                        accountId);
                    return Result<Unit, FailureBase>.Err(
                        MembershipFailure.ValidationFailed("Invalid HMAC authentication proof"));
                }

                Log.Information("[LOGOUT-HMAC] HMAC validation succeeded for AccountId: {AccountId}",
                    accountId);
                return Result<Unit, FailureBase>.Ok(Unit.Value);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(canonicalBytes);
            }
        }
        finally
        {
            masterKeyHandle?.Dispose();
            if (logoutHmacKey != null)
            {
                CryptographicOperations.ZeroMemory(logoutHmacKey);
            }
        }
    }

    private static string BuildCanonicalLogoutRequest(LogoutRequest request)
    {
        return $"logout:v1:{request.MembershipIdentifier.ToBase64()}:" +
               $"{request.Timestamp}:{request.Scope}:{request.LogoutReason}";
    }

    private Task<byte[]> CaptureRatchetFingerprintAsync(uint connectId)
    {
        // RatchetState is now a legacy placeholder - fingerprinting disabled
        Log.Debug("[LOGOUT-RATCHET] Ratchet fingerprinting disabled for ConnectId: {ConnectId}", connectId);
        return Task.FromResult<byte[]>([]);
    }

    private async Task<byte[]> GenerateHmacRevocationProofAsync(
        Guid accountId,
        Guid membershipId,
        uint connectId,
        long serverTimestamp,
        byte[] ratchetFingerprint)
    {
        const byte proofVersionHmac = 1;
        const int nonceSize = 16;

        SodiumSecureMemoryHandle? masterKeyHandle = null;
        byte[]? proofKey = null;

        try
        {
            Result<dynamic, FailureBase> handleResult =
                await _masterKeyService.GetMasterKeyHandleAsync(accountId);

            if (handleResult.IsErr)
            {
                FailureBase failure = handleResult.UnwrapErr();
                throw new InvalidOperationException(
                    $"Unable to generate revocation proof without master key handle for AccountId: {accountId}. Error: {failure.Message}");
            }

            masterKeyHandle = (SodiumSecureMemoryHandle)handleResult.Unwrap();

            Result<byte[], SodiumFailure> proofKeyResult =
                LogoutKeyDerivation.DeriveLogoutProofKey(masterKeyHandle);

            if (proofKeyResult.IsErr)
            {
                SodiumFailure failure = proofKeyResult.UnwrapErr();
                throw new InvalidOperationException(
                    $"Unable to derive logout proof key for AccountId: {accountId}. Error: {failure.Message}");
            }

            proofKey = proofKeyResult.Unwrap();

            byte[] nonce = RandomNumberGenerator.GetBytes(nonceSize);

            using MemoryStream canonicalStream = new();
            await using BinaryWriter canonicalWriter = new(canonicalStream);

            canonicalWriter.Write(membershipId.ToByteArray());
            canonicalWriter.Write(connectId);
            canonicalWriter.Write(serverTimestamp);
            canonicalWriter.Write(ratchetFingerprint.Length);
            if (ratchetFingerprint.Length > 0)
            {
                canonicalWriter.Write(ratchetFingerprint);
            }

            canonicalWriter.Write(nonce);

            canonicalWriter.Flush();
            byte[] canonicalProofData = canonicalStream.ToArray();

            byte[] hmacProof = LogoutKeyDerivation.ComputeHmac(proofKey, canonicalProofData);

            Log.Information(
                "[LOGOUT-PROOF] Generated HMAC revocation proof for AccountId: {AccountId}, ProofTagPrefix: {ProofTagPrefix}",
                accountId, Convert.ToHexString(hmacProof).ToLowerInvariant()[..16]);

            using MemoryStream proofStream = new();
            await using BinaryWriter proofWriter = new(proofStream);

            proofWriter.Write(proofVersionHmac);
            proofWriter.Write(nonce.Length);
            proofWriter.Write(nonce);
            proofWriter.Write(ratchetFingerprint.Length);
            if (ratchetFingerprint.Length > 0)
            {
                proofWriter.Write(ratchetFingerprint);
            }

            proofWriter.Write(hmacProof);

            proofWriter.Flush();
            return proofStream.ToArray();
        }
        finally
        {
            masterKeyHandle?.Dispose();
            if (proofKey != null)
            {
                CryptographicOperations.ZeroMemory(proofKey);
            }
        }
    }

    private async Task<Result<LogoutResponse, FailureBase>> ProcessLogoutAsync(
        LogoutRequest message,
        uint connectId,
        ServerCallContext context,
        CancellationToken cancellationToken)
    {
        Guid membershipId = Helpers.FromByteStringToGuid(message.MembershipIdentifier);
        long serverTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        Result<Guid, FailureBase> accountResult =
            await ResolveAccountIdAsync(membershipId, message.AccountIdentifier, cancellationToken);

        if (accountResult.IsErr)
        {
            Log.Warning("[LOGOUT] Failed to resolve account for MembershipId: {MembershipId}. Error: {Error}",
                membershipId, accountResult.UnwrapErr().Message);
            return Result<LogoutResponse, FailureBase>.Ok(new LogoutResponse
            {
                Result = LogoutResponse.Types.Result.SessionNotFound, ServerTimestamp = serverTimestamp
            });
        }

        Guid accountId = accountResult.Unwrap();

        Result<Unit, LogoutResponse> validationResult =
            await PerformValidationChecksAsync(message, membershipId, accountId, serverTimestamp);

        if (validationResult.IsErr)
        {
            return Result<LogoutResponse, FailureBase>.Ok(validationResult.UnwrapErr());
        }

        LogoutReason reason = ParseLogoutReason(message.LogoutReason);
        Guid deviceId = DeviceIdResolver.ResolveDeviceIdFromContext(context);

        await RecordLogoutAuditAsync(membershipId, accountId, deviceId, reason, cancellationToken);

        byte[] ratchetFingerprint = await CaptureRatchetFingerprintAsync(connectId);
        byte[] revocationProof = await GenerateHmacRevocationProofAsync(
            accountId, membershipId, connectId, serverTimestamp, ratchetFingerprint);

        ScheduleProtocolCleanup(connectId);

        Log.Information("Logout completed for ConnectId: {ConnectId}. Protocol cleanup scheduled", connectId);

        return Result<LogoutResponse, FailureBase>.Ok(new LogoutResponse
        {
            Result = LogoutResponse.Types.Result.Succeeded,
            ServerTimestamp = serverTimestamp,
            RevocationProof = Google.Protobuf.ByteString.CopyFrom(revocationProof)
        });
    }

    private async Task<Result<Unit, LogoutResponse>> PerformValidationChecksAsync(
        LogoutRequest message, Guid membershipId, Guid accountId, long serverTimestamp)
    {
        long timestampDrift = Math.Abs(serverTimestamp - message.Timestamp);
        long maxDrift = (long)_securityConfig.GrpcSecurity.MaxTimestampDrift.TotalSeconds;

        if (timestampDrift > maxDrift)
        {
            return Result<Unit, LogoutResponse>.Err(new LogoutResponse
            {
                Result = LogoutResponse.Types.Result.InvalidTimestamp, ServerTimestamp = serverTimestamp
            });
        }

        Result<bool, FailureBase> sharesExistResult =
            await _masterKeyService.CheckSharesExistAsync(accountId);

        if (sharesExistResult.IsErr || !sharesExistResult.Unwrap())
        {
            return Result<Unit, LogoutResponse>.Err(new LogoutResponse
            {
                Result = LogoutResponse.Types.Result.SessionNotFound, ServerTimestamp = serverTimestamp
            });
        }

        Result<Unit, FailureBase> hmacValidation = await ValidateLogoutHmacAsync(message, accountId);
        if (hmacValidation.IsErr)
        {
            return Result<Unit, LogoutResponse>.Err(new LogoutResponse
            {
                Result = LogoutResponse.Types.Result.InvalidHmac, ServerTimestamp = serverTimestamp
            });
        }

        return Result<Unit, LogoutResponse>.Ok(Unit.Value);
    }

    private static LogoutReason ParseLogoutReason(string protoReason)
    {
        if (!string.IsNullOrEmpty(protoReason) && Enum.TryParse(protoReason, true, out LogoutReason reason))
        {
            return reason;
        }

        return LogoutReason.UserInitiated;
    }

    private async Task RecordLogoutAuditAsync(Guid membershipId, Guid? accountId, Guid deviceId, LogoutReason reason,
        CancellationToken cancellationToken)
    {
        RecordLogoutEvent logoutEvent = new(membershipId, accountId, deviceId, reason,
            "", "", cancellationToken);

        Task<Result<Unit, LogoutFailure>> auditTask =
            _logoutAuditPersistor.Ask<Result<Unit, LogoutFailure>>(
                logoutEvent,
                TimeoutConfiguration.Actor.AskTimeout);

        Result<Unit, LogoutFailure> auditResult =
            await auditTask.WaitAsync(cancellationToken).ConfigureAwait(false);

        if (auditResult.IsErr)
        {
            Log.Warning("Failed to record logout audit, but continuing with logout: {Error}",
                auditResult.UnwrapErr().Message);
        }
    }

    private void ScheduleProtocolCleanup(uint connectId)
    {
        _ = Task.Run(async () =>
        {
            await Task.Delay(2000);
            _actorSystem.EventStream.Publish(new ProtocolCleanupRequiredEvent(connectId));
            Log.Information("Protocol cleanup event published for ConnectId: {ConnectId}", connectId);
        });
    }

    public async Task<SecureEnvelope> Logout(SecureEnvelope request, ServerCallContext context)
    {
        SecureEnvelope response = await _service.ExecuteEncryptedOperationAsync<LogoutRequest, LogoutResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                try
                {
                    return await ProcessLogoutAsync(message, connectId, context, cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error during logout for ConnectId: {ConnectId}", connectId);
                    return Result<LogoutResponse, FailureBase>.Ok(new LogoutResponse
                    {
                        Result = LogoutResponse.Types.Result.Failed,
                        ServerTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                    });
                }
            });

        return response;
    }

    private async Task<Result<Unit, FailureBase>> ValidateAnonymousLogoutHmacAsync(
        AnonymousLogoutRequest message,
        Guid accountId)
    {
        if (message.HmacProof == null || message.HmacProof.IsEmpty)
        {
            Log.Warning("[LOGOUT-ANONYMOUS-HMAC] Missing HMAC proof for AccountId: {AccountId}", accountId);
            return Result<Unit, FailureBase>.Err(
                VerificationFlowFailure.Unauthorized("Missing HMAC authentication proof"));
        }

        SodiumSecureMemoryHandle? masterKeyHandle = null;
        byte[]? logoutHmacKey = null;

        try
        {
            Result<dynamic, FailureBase> handleResult =
                await _masterKeyService.GetMasterKeyHandleAsync(accountId);

            if (handleResult.IsErr)
            {
                Log.Error(
                    "[LOGOUT-ANONYMOUS-HMAC] Failed to retrieve master key handle for AccountId: {AccountId}",
                    accountId);
                return Result<Unit, FailureBase>.Err(handleResult.UnwrapErr());
            }

            masterKeyHandle = (SodiumSecureMemoryHandle)handleResult.Unwrap();

            Result<byte[], SodiumFailure> hmacKeyResult =
                LogoutKeyDerivation.DeriveLogoutHmacKey(masterKeyHandle);

            if (hmacKeyResult.IsErr)
            {
                Log.Error("[LOGOUT-ANONYMOUS-HMAC] Failed to derive logout HMAC key for AccountId: {AccountId}",
                    accountId);
                return Result<Unit, FailureBase>.Err(
                    VerificationFlowFailure.Unauthorized(
                        $"HMAC key derivation failed: {hmacKeyResult.UnwrapErr().Message}"));
            }

            logoutHmacKey = hmacKeyResult.Unwrap();

            string canonical = BuildCanonicalAnonymousLogoutRequest(message);
            int maxByteCount = System.Text.Encoding.UTF8.GetMaxByteCount(canonical.Length);
            byte[]? canonicalBytes = ArrayPool<byte>.Shared.Rent(maxByteCount);

            try
            {
                int actualByteCount = System.Text.Encoding.UTF8.GetBytes(canonical, canonicalBytes);
                byte[] canonicalData = canonicalBytes.AsSpan(0, actualByteCount).ToArray();

                byte[] clientHmac = message.HmacProof.ToByteArray();
                bool isValid = LogoutKeyDerivation.VerifyHmac(logoutHmacKey, canonicalData, clientHmac);

                if (!isValid)
                {
                    Log.Warning("[LOGOUT-ANONYMOUS-HMAC] HMAC verification failed for AccountId: {AccountId}",
                        accountId);
                    return Result<Unit, FailureBase>.Err(
                        VerificationFlowFailure.Unauthorized("Invalid HMAC authentication proof"));
                }

                Log.Information("[LOGOUT-ANONYMOUS-HMAC] HMAC validation succeeded for AccountId: {AccountId}",
                    accountId);
                return Result<Unit, FailureBase>.Ok(Unit.Value);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(canonicalBytes);
            }
        }
        finally
        {
            masterKeyHandle?.Dispose();
            if (logoutHmacKey != null)
            {
                CryptographicOperations.ZeroMemory(logoutHmacKey);
            }
        }
    }

    private static string BuildCanonicalAnonymousLogoutRequest(AnonymousLogoutRequest request)
    {
        return $"logout:v1:{request.MembershipIdentifier.ToBase64()}:" +
               $"{request.Timestamp}:{request.Scope}:{request.LogoutReason}";
    }

    private async Task<Result<AnonymousLogoutResponse, FailureBase>> ProcessAnonymousLogoutAsync(
        AnonymousLogoutRequest message,
        uint connectId,
        ServerCallContext context,
        CancellationToken cancellationToken)
    {
        Guid membershipId = Helpers.FromByteStringToGuid(message.MembershipIdentifier);
        long serverTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        Result<Guid, FailureBase> accountResult =
            await ResolveAccountIdAsync(membershipId, message.AccountIdentifier, cancellationToken);

        if (accountResult.IsErr)
        {
            Log.Warning(
                "[LOGOUT-ANONYMOUS] Failed to resolve account for MembershipId: {MembershipId}. Error: {Error}",
                membershipId, accountResult.UnwrapErr().Message);
            return Result<AnonymousLogoutResponse, FailureBase>.Ok(new AnonymousLogoutResponse
            {
                Result = AnonymousLogoutResponse.Types.Result.SessionNotFound,
                ServerTimestamp = serverTimestamp,
                Message = "Session not found"
            });
        }

        Guid accountId = accountResult.Unwrap();

        Result<Unit, AnonymousLogoutResponse> validationResult =
            await PerformAnonymousValidationChecksAsync(message, membershipId, accountId, serverTimestamp);

        if (validationResult.IsErr)
        {
            return Result<AnonymousLogoutResponse, FailureBase>.Ok(validationResult.UnwrapErr());
        }

        LogoutReason reason = ParseLogoutReason(message.LogoutReason);
        Guid deviceId = DeviceIdResolver.ResolveDeviceIdFromContext(context);

        Log.Information(
            "[LOGOUT-ANONYMOUS] Processing anonymous logout for MembershipId: {MembershipId}, ConnectId: {ConnectId}, DeviceId: {DeviceId}, AccountId: {AccountId}, Reason: {Reason}, Scope: {Scope}",
            membershipId, connectId, deviceId, accountId, reason, message.Scope);

        await RecordLogoutAuditAsync(membershipId, accountId, deviceId, reason, cancellationToken);

        ScheduleProtocolCleanup(connectId);

        return Result<AnonymousLogoutResponse, FailureBase>.Ok(new AnonymousLogoutResponse
        {
            Result = AnonymousLogoutResponse.Types.Result.Succeeded,
            ServerTimestamp = serverTimestamp,
            Message = "Logout successful"
        });
    }

    private async Task<Result<Unit, AnonymousLogoutResponse>> PerformAnonymousValidationChecksAsync(
        AnonymousLogoutRequest message, Guid membershipId, Guid accountId, long serverTimestamp)
    {
        long timestampDrift = Math.Abs(serverTimestamp - message.Timestamp);
        const long maxWindowSeconds = 72 * 3600;

        if (timestampDrift > maxWindowSeconds)
        {
            Log.Warning(
                "[LOGOUT-ANONYMOUS] Timestamp outside 72-hour window for MembershipId: {MembershipId}. Drift: {Drift}s",
                membershipId, timestampDrift);

            return Result<Unit, AnonymousLogoutResponse>.Err(new AnonymousLogoutResponse
            {
                Result = AnonymousLogoutResponse.Types.Result.TimestampTooOld,
                ServerTimestamp = serverTimestamp,
                Message = "Logout request older than 72 hours"
            });
        }

        Result<bool, FailureBase> sharesExistResult =
            await _masterKeyService.CheckSharesExistAsync(accountId);

        if (sharesExistResult.IsErr)
        {
            Log.Error(
                "[LOGOUT-ANONYMOUS] Failed to check shares for MembershipId: {MembershipId}. Error: {Error}",
                membershipId, sharesExistResult.UnwrapErr().Message);

            return Result<Unit, AnonymousLogoutResponse>.Err(new AnonymousLogoutResponse
            {
                Result = AnonymousLogoutResponse.Types.Result.SessionNotFound,
                ServerTimestamp = serverTimestamp,
                Message = "Session not found"
            });
        }

        if (!sharesExistResult.Unwrap())
        {
            return Result<Unit, AnonymousLogoutResponse>.Err(new AnonymousLogoutResponse
            {
                Result = AnonymousLogoutResponse.Types.Result.AlreadyLoggedOut,
                ServerTimestamp = serverTimestamp,
                Message = "Already logged out"
            });
        }

        Log.Debug("[LOGOUT-ANONYMOUS] Master key shares verified for MembershipId: {MembershipId}", membershipId);

        Result<Unit, FailureBase> hmacValidation =
            await ValidateAnonymousLogoutHmacAsync(message, accountId);
        if (hmacValidation.IsErr)
        {
            Log.Warning("[LOGOUT-ANONYMOUS] HMAC validation failed for MembershipId: {MembershipId}",
                membershipId);

            return Result<Unit, AnonymousLogoutResponse>.Err(new AnonymousLogoutResponse
            {
                Result = AnonymousLogoutResponse.Types.Result.InvalidHmac,
                ServerTimestamp = serverTimestamp,
                Message = "Invalid HMAC proof"
            });
        }

        return Result<Unit, AnonymousLogoutResponse>.Ok(Unit.Value);
    }

    public async Task<SecureEnvelope> AnonymousLogout(SecureEnvelope request, ServerCallContext context)
    {
        SecureEnvelope response =
            await _service.ExecuteEncryptedOperationAsync<AnonymousLogoutRequest, AnonymousLogoutResponse>(
                request, context,
                async (message, connectId, _, cancellationToken) =>
                {
                    try
                    {
                        return await ProcessAnonymousLogoutAsync(message, connectId, context, cancellationToken);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "[LOGOUT-ANONYMOUS] Error during anonymous logout for ConnectId: {ConnectId}",
                            connectId);
                        return Result<AnonymousLogoutResponse, FailureBase>.Ok(new AnonymousLogoutResponse
                        {
                            Result = AnonymousLogoutResponse.Types.Result.Failed,
                            ServerTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                            Message = "Internal server error"
                        });
                    }
                });

        return response;
    }

    public Task<SecureEnvelope> GetMasterKeyShares(SecureEnvelope _, ServerCallContext __) =>
        Task.FromException<SecureEnvelope>(new RpcException(new Status(StatusCode.Unimplemented,
            "GetMasterKeyShares is not implemented in gateway mode")));

}
