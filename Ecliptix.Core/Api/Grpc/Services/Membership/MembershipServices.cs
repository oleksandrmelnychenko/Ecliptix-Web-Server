using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.Core.Api.Grpc.Base;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Infrastructure.Grpc.Utilities;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Services.KeyDerivation;
using Ecliptix.Domain.Memberships.ActorEvents.Account;
using Ecliptix.Domain.Memberships.ActorEvents.Logout;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.MobileNumberValidation;
using Ecliptix.Domain.Memberships.WorkerActors.Membership;
using Ecliptix.Domain.Memberships.WorkerActors.VerificationFlow;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Domain.Services.Security;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Ecliptix.Utilities.Failures;
using Ecliptix.Utilities.Failures.Sodium;
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

namespace Ecliptix.Core.Api.Grpc.Services.Membership;

internal sealed class MembershipServices : Protobuf.Membership.MembershipServices.MembershipServicesBase
{
    private readonly GrpcSecurityService _service;
    private readonly IActorRef _membershipActor;
    private readonly IActorRef _logoutAuditPersistor;
    private readonly IActorRef _protocolActor;
    private readonly IMobileNumberValidator _phoneNumberValidator;
    private readonly IMasterKeyService _masterKeyService;
    private readonly ActorSystem _actorSystem;
    private readonly string _cultureName = CultureInfo.CurrentCulture.Name;
    private readonly SecurityConfiguration _securityConfig;

    public MembershipServices(
        IEcliptixActorRegistry actorRegistry,
        IMobileNumberValidator phoneNumberValidator,
        IGrpcCipherService grpcCipherService,
        ActorSystem actorSystem,
        IMasterKeyService masterKeyService,
        IOptions<SecurityConfiguration> securityConfig)
    {
        _service = new GrpcSecurityService(grpcCipherService, securityConfig);
        _membershipActor = actorRegistry.Get(ActorIds.MembershipActor);
        _logoutAuditPersistor = actorRegistry.Get(ActorIds.LogoutAuditPersistorActor);
        _protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);
        _phoneNumberValidator = phoneNumberValidator;
        _masterKeyService = masterKeyService;
        _actorSystem = actorSystem;
        _securityConfig = securityConfig.Value;
    }

    public override async Task<SecureEnvelope> OpaqueSignInInitRequest(SecureEnvelope request,
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

    public override async Task<SecureEnvelope> OpaqueSignInCompleteRequest(SecureEnvelope request,
        ServerCallContext context)
    {
        return await _service
            .ExecuteEncryptedOperationAsync<OpaqueSignInFinalizeRequest, OpaqueSignInFinalizeResponse>(
                request, context,
                async (message, connectId, idempotencyKey, cancellationToken) =>
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

    public override async Task<SecureEnvelope> OpaqueRegistrationCompleteRequest(SecureEnvelope request,
        ServerCallContext context)
    {
        return await _service
            .ExecuteEncryptedOperationAsync<OprfRegistrationCompleteRequest, OprfRegistrationCompleteResponse>(request,
                context,
                async (message, _, _, cancellationToken) =>
                {
                    CompleteRegistrationRecordActorEvent @event = new(
                        Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                        Helpers.ReadMemoryToRetrieveBytes(message.PeerRegistrationRecord.Memory),
                        Helpers.ReadMemoryToRetrieveBytes(message.MasterKey.Memory),
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
                });
    }

    public override async Task<SecureEnvelope> OpaqueRecoverySecretKeyCompleteRequest(SecureEnvelope request,
        ServerCallContext context)
    {
        return await _service
            .ExecuteEncryptedOperationAsync<OprfRecoverySecretKeyCompleteRequest,
                OprfRecoverySecretKeyCompleteResponse>(
                request, context,
                async (message, _, _, cancellationToken) =>
                {
                    OprfCompleteRecoverySecureKeyEvent @event = new(
                        Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                        Helpers.ReadMemoryToRetrieveBytes(message.PeerRecoveryRecord.Memory),
                        Helpers.ReadMemoryToRetrieveBytes(message.MasterKey.Memory),
                        cancellationToken);

                    Task<Result<OprfRecoverySecretKeyCompleteResponse, PasswordRecoveryFailure>>
                        completeRecoverySecretKeyTask =
                            _membershipActor
                                .Ask<Result<OprfRecoverySecretKeyCompleteResponse, PasswordRecoveryFailure>>(
                                    @event,
                                    TimeoutConfiguration.Actor.AskTimeout);

                    Result<OprfRecoverySecretKeyCompleteResponse, PasswordRecoveryFailure>
                        completeRecoverySecretKeyResult =
                            await completeRecoverySecretKeyTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                    return completeRecoverySecretKeyResult.Match(
                        ok: Result<OprfRecoverySecretKeyCompleteResponse, FailureBase>.Ok,
                        err: Result<OprfRecoverySecretKeyCompleteResponse, FailureBase>.Err
                    );
                });
    }

    public override async Task<SecureEnvelope> OpaqueRegistrationInitRequest(SecureEnvelope request,
        ServerCallContext context)
    {
        return await _service
            .ExecuteEncryptedOperationAsync<OprfRegistrationInitRequest, OprfRegistrationInitResponse>(
                request, context,
                async (message, _, idempotencyKey, cancellationToken) =>
                {
                    GenerateMembershipOprfRegistrationRequestEvent @event = new(
                        Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                        Helpers.ReadMemoryToRetrieveBytes(message.PeerOprf.Memory),
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
                });
    }

    public override async Task<SecureEnvelope> OpaqueRecoverySecretKeyInitRequest(SecureEnvelope request,
        ServerCallContext context)
    {
        return await _service
            .ExecuteEncryptedOperationAsync<OprfRecoverySecureKeyInitRequest, OprfRecoverySecureKeyInitResponse>(
                request, context,
                async (message, _, _, cancellationToken) =>
                {
                    OprfInitRecoverySecureKeyEvent @event = new(
                        Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                        Helpers.ReadMemoryToRetrieveBytes(message.PeerOprf.Memory),
                        _cultureName,
                        cancellationToken);

                    Task<Result<OprfRecoverySecureKeyInitResponse, PasswordRecoveryFailure>> recoveryInitTask =
                        _membershipActor.Ask<Result<OprfRecoverySecureKeyInitResponse, PasswordRecoveryFailure>>(
                            @event,
                            TimeoutConfiguration.Actor.AskTimeout);

                    Result<OprfRecoverySecureKeyInitResponse, PasswordRecoveryFailure> result =
                        await recoveryInitTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                    return result.Match(
                        ok: Result<OprfRecoverySecureKeyInitResponse, FailureBase>.Ok,
                        err: Result<OprfRecoverySecureKeyInitResponse, FailureBase>.Err
                    );
                }
            );
    }

    private async Task<Result<Unit, FailureBase>> ValidateLogoutHmacAsync(
        LogoutRequest message,
        Guid membershipId)
    {
        if (message.HmacProof == null || message.HmacProof.IsEmpty)
        {
            Log.Warning("[LOGOUT-HMAC] Missing HMAC proof for MembershipId: {MembershipId}", membershipId);
            return Result<Unit, FailureBase>.Err(
                MembershipFailure.ValidationFailed("Missing HMAC authentication proof"));
        }

        SodiumSecureMemoryHandle? masterKeyHandle = null;
        byte[]? logoutHmacKey = null;

        try
        {
            Result<dynamic, FailureBase> handleResult =
                await _masterKeyService.GetMasterKeyHandleAsync(membershipId);

            if (handleResult.IsErr)
            {
                Log.Error("[LOGOUT-HMAC] Failed to retrieve master key handle for MembershipId: {MembershipId}",
                    membershipId);
                return Result<Unit, FailureBase>.Err(handleResult.UnwrapErr());
            }

            masterKeyHandle = (SodiumSecureMemoryHandle)handleResult.Unwrap();

            Result<byte[], SodiumFailure> hmacKeyResult =
                LogoutKeyDerivation.DeriveLogoutHmacKey(masterKeyHandle);

            if (hmacKeyResult.IsErr)
            {
                Log.Error("[LOGOUT-HMAC] Failed to derive logout HMAC key for MembershipId: {MembershipId}",
                    membershipId);
                return Result<Unit, FailureBase>.Err(
                    MembershipFailure.ValidationFailed(
                        $"HMAC key derivation failed: {hmacKeyResult.UnwrapErr().Message}"));
            }

            logoutHmacKey = hmacKeyResult.Unwrap();

            string canonical = BuildCanonicalLogoutRequest(message);
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
                    Log.Warning("[LOGOUT-HMAC] HMAC verification failed for MembershipId: {MembershipId}",
                        membershipId);
                    return Result<Unit, FailureBase>.Err(
                        MembershipFailure.ValidationFailed("Invalid HMAC authentication proof"));
                }

                Log.Information("[LOGOUT-HMAC] HMAC validation succeeded for MembershipId: {MembershipId}",
                    membershipId);
                return Result<Unit, FailureBase>.Ok(Unit.Value);
            }
            finally
            {
                if (canonicalBytes != null)
                {
                    ArrayPool<byte>.Shared.Return(canonicalBytes);
                }
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

    private string BuildCanonicalLogoutRequest(LogoutRequest request)
    {
        return $"logout:v1:{request.MembershipIdentifier.ToBase64()}:" +
               $"{request.Timestamp}:{request.Scope}:{request.LogoutReason}";
    }

    private async Task<byte[]> CaptureRatchetFingerprintAsync(uint connectId)
    {
        try
        {
            Log.Information("[LOGOUT-RATCHET] Capturing ratchet fingerprint for ConnectId: {ConnectId}", connectId);

            GetProtocolStateActorEvent queryEvent = new(connectId);
            ForwardToConnectActorEvent forwardEvent = new(connectId, queryEvent);

            Task<GetProtocolStateReply> queryTask =
                _protocolActor.Ask<GetProtocolStateReply>(
                    forwardEvent,
                    TimeoutConfiguration.Actor.AskTimeout);

            GetProtocolStateReply reply = await queryTask.ConfigureAwait(false);

            if (reply.SessionState == null)
            {
                Log.Warning(
                    "[LOGOUT-RATCHET] No session state found for ConnectId: {ConnectId}, returning empty fingerprint",
                    connectId);
                return [];
            }

            byte[] fingerprint = RatchetStateHasher.ComputeRatchetFingerprint(reply.SessionState);

            Log.Information(
                "[LOGOUT-RATCHET] Ratchet fingerprint captured for ConnectId: {ConnectId}, FingerprintSize: {Size} bytes",
                connectId, fingerprint.Length);

            return fingerprint;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[LOGOUT-RATCHET] Failed to capture ratchet fingerprint for ConnectId: {ConnectId}",
                connectId);
            return [];
        }
    }

    private async Task<byte[]> GenerateHmacRevocationProofAsync(
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
                await _masterKeyService.GetMasterKeyHandleAsync(membershipId);

            if (handleResult.IsErr)
            {
                FailureBase failure = handleResult.UnwrapErr();
                throw new InvalidOperationException(
                    $"Unable to generate revocation proof without master key handle for MembershipId: {membershipId}. Error: {failure.Message}");
            }

            masterKeyHandle = (SodiumSecureMemoryHandle)handleResult.Unwrap();

            Result<byte[], SodiumFailure> proofKeyResult =
                LogoutKeyDerivation.DeriveLogoutProofKey(masterKeyHandle);

            if (proofKeyResult.IsErr)
            {
                SodiumFailure failure = proofKeyResult.UnwrapErr();
                throw new InvalidOperationException(
                    $"Unable to derive logout proof key for MembershipId: {membershipId}. Error: {failure.Message}");
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
                "[LOGOUT-PROOF] Generated HMAC revocation proof for MembershipId: {MembershipId}, ProofTagPrefix: {ProofTagPrefix}",
                membershipId, Convert.ToHexString(hmacProof).ToLowerInvariant()[..16]);

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

    public override async Task<SecureEnvelope> Logout(SecureEnvelope request, ServerCallContext context)
    {
        SecureEnvelope response = await _service.ExecuteEncryptedOperationAsync<LogoutRequest, LogoutResponse>(
            request, context,
            async (message, connectId, idempotencyKey, cancellationToken) =>
            {
                try
                {
                    Guid membershipId = Helpers.FromByteStringToGuid(message.MembershipIdentifier);
                    long serverTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                    long timestampDrift = Math.Abs(serverTimestamp - message.Timestamp);
                    long maxDrift = (long)_securityConfig.GrpcSecurity.MaxTimestampDrift.TotalSeconds;

                    if (timestampDrift > maxDrift)
                    {
                        Log.Warning("[LOGOUT-SECURITY] Timestamp drift exceeded for MembershipId: {MembershipId}. " +
                                    "ClientTimestamp: {ClientTimestamp}, ServerTimestamp: {ServerTimestamp}, Drift: {Drift}s, MaxDrift: {MaxDrift}s",
                            membershipId, message.Timestamp, serverTimestamp, timestampDrift, maxDrift);
                        return Result<LogoutResponse, FailureBase>.Ok(new LogoutResponse
                        {
                            Result = LogoutResponse.Types.Result.InvalidTimestamp, ServerTimestamp = serverTimestamp
                        });
                    }

                    Result<bool, FailureBase> sharesExistResult =
                        await _masterKeyService.CheckSharesExistAsync(membershipId);

                    if (sharesExistResult.IsErr)
                    {
                        Log.Error(
                            "[LOGOUT-SECURITY] Failed to check master key shares existence for MembershipId: {MembershipId}. Error: {Error}",
                            membershipId, sharesExistResult.UnwrapErr().Message);
                        return Result<LogoutResponse, FailureBase>.Ok(new LogoutResponse
                        {
                            Result = LogoutResponse.Types.Result.SessionNotFound, ServerTimestamp = serverTimestamp
                        });
                    }

                    bool sharesExist = sharesExistResult.Unwrap();
                    if (!sharesExist)
                    {
                        Log.Warning("[LOGOUT-SECURITY] No master key shares found for MembershipId: {MembershipId}. " +
                                    "Session was restored but shares don't exist in database. User must sign in again.",
                            membershipId);
                        return Result<LogoutResponse, FailureBase>.Ok(new LogoutResponse
                        {
                            Result = LogoutResponse.Types.Result.SessionNotFound, ServerTimestamp = serverTimestamp
                        });
                    }

                    Log.Debug("[LOGOUT-SECURITY] Master key shares verified for MembershipId: {MembershipId}",
                        membershipId);

                    Result<Unit, FailureBase> hmacValidation = await ValidateLogoutHmacAsync(message, membershipId);
                    if (hmacValidation.IsErr)
                    {
                        Log.Warning("[LOGOUT-SECURITY] HMAC validation failed for MembershipId: {MembershipId}",
                            membershipId);
                        return Result<LogoutResponse, FailureBase>.Ok(new LogoutResponse
                        {
                            Result = LogoutResponse.Types.Result.InvalidHmac, ServerTimestamp = serverTimestamp
                        });
                    }

                    LogoutReason reason = LogoutReason.UserInitiated;
                    if (!string.IsNullOrEmpty(message.LogoutReason))
                    {
                        if (!Enum.TryParse(message.LogoutReason, true, out reason))
                        {
                            reason = LogoutReason.UserInitiated;
                        }
                    }

                    Guid deviceId = DeviceIdResolver.ResolveDeviceIdFromContext(context);
                    Guid? accountId = message.AccountIdentifier != null && message.AccountIdentifier.Length > 0
                        ? Helpers.FromByteStringToGuid(message.AccountIdentifier)
                        : null;

                    Log.Information(
                        "Processing logout for MembershipId: {MembershipId}, ConnectId: {ConnectId}, DeviceId: {DeviceId}, AccountId: {AccountId}, Reason: {Reason}, Scope: {Scope}",
                        membershipId, connectId, deviceId, accountId, reason, message.Scope);

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

                    byte[] ratchetFingerprint = await CaptureRatchetFingerprintAsync(connectId);

                    byte[] revocationProof = await GenerateHmacRevocationProofAsync(
                        membershipId, connectId, serverTimestamp, ratchetFingerprint);

                    _ = Task.Run(async () =>
                    {
                        await Task.Delay(2000);
                        _actorSystem.EventStream.Publish(new ProtocolCleanupRequiredEvent(connectId));
                        Log.Information("Protocol cleanup event published for ConnectId: {ConnectId}", connectId);
                    });

                    Log.Information("Logout completed for ConnectId: {ConnectId}. Protocol cleanup scheduled.",
                        connectId);

                    return Result<LogoutResponse, FailureBase>.Ok(new LogoutResponse
                    {
                        Result = LogoutResponse.Types.Result.Succeeded,
                        ServerTimestamp = serverTimestamp,
                        RevocationProof = Google.Protobuf.ByteString.CopyFrom(revocationProof)
                    });
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
        Guid membershipId)
    {
        if (message.HmacProof == null || message.HmacProof.IsEmpty)
        {
            Log.Warning("[LOGOUT-ANONYMOUS-HMAC] Missing HMAC proof for MembershipId: {MembershipId}", membershipId);
            return Result<Unit, FailureBase>.Err(
                VerificationFlowFailure.Unauthorized("Missing HMAC authentication proof"));
        }

        SodiumSecureMemoryHandle? masterKeyHandle = null;
        byte[]? logoutHmacKey = null;

        try
        {
            Result<dynamic, FailureBase> handleResult =
                await _masterKeyService.GetMasterKeyHandleAsync(membershipId);

            if (handleResult.IsErr)
            {
                Log.Error(
                    "[LOGOUT-ANONYMOUS-HMAC] Failed to retrieve master key handle for MembershipId: {MembershipId}",
                    membershipId);
                return Result<Unit, FailureBase>.Err(handleResult.UnwrapErr());
            }

            masterKeyHandle = (SodiumSecureMemoryHandle)handleResult.Unwrap();

            Result<byte[], SodiumFailure> hmacKeyResult =
                LogoutKeyDerivation.DeriveLogoutHmacKey(masterKeyHandle);

            if (hmacKeyResult.IsErr)
            {
                Log.Error("[LOGOUT-ANONYMOUS-HMAC] Failed to derive logout HMAC key for MembershipId: {MembershipId}",
                    membershipId);
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
                    Log.Warning("[LOGOUT-ANONYMOUS-HMAC] HMAC verification failed for MembershipId: {MembershipId}",
                        membershipId);
                    return Result<Unit, FailureBase>.Err(
                        VerificationFlowFailure.Unauthorized("Invalid HMAC authentication proof"));
                }

                Log.Information("[LOGOUT-ANONYMOUS-HMAC] HMAC validation succeeded for MembershipId: {MembershipId}",
                    membershipId);
                return Result<Unit, FailureBase>.Ok(Unit.Value);
            }
            finally
            {
                if (canonicalBytes != null)
                {
                    ArrayPool<byte>.Shared.Return(canonicalBytes);
                }
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

    private string BuildCanonicalAnonymousLogoutRequest(AnonymousLogoutRequest request)
    {
        return $"logout:v1:{request.MembershipIdentifier.ToBase64()}:" +
               $"{request.Timestamp}:{request.Scope}:{request.LogoutReason}";
    }

    public override async Task<SecureEnvelope> AnonymousLogout(SecureEnvelope request, ServerCallContext context)
    {
        SecureEnvelope response =
            await _service.ExecuteEncryptedOperationAsync<AnonymousLogoutRequest, AnonymousLogoutResponse>(
                request, context,
                async (message, connectId, idempotencyKey, cancellationToken) =>
                {
                    try
                    {
                        Guid membershipId = Helpers.FromByteStringToGuid(message.MembershipIdentifier);
                        long serverTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                        long timestampDrift = Math.Abs(serverTimestamp - message.Timestamp);
                        const long maxWindowSeconds = 72 * 3600;

                        if (timestampDrift > maxWindowSeconds)
                        {
                            Log.Warning(
                                "[LOGOUT-ANONYMOUS] Timestamp outside 72-hour window for MembershipId: {MembershipId}. " +
                                "ClientTimestamp: {ClientTimestamp}, ServerTimestamp: {ServerTimestamp}, Drift: {Drift}s, MaxWindow: {MaxWindow}s",
                                membershipId, message.Timestamp, serverTimestamp, timestampDrift, maxWindowSeconds);
                            return Result<AnonymousLogoutResponse, FailureBase>.Ok(new AnonymousLogoutResponse
                            {
                                Result = AnonymousLogoutResponse.Types.Result.TimestampTooOld,
                                ServerTimestamp = serverTimestamp,
                                Message = "Logout request older than 72 hours"
                            });
                        }

                        Result<bool, FailureBase> sharesExistResult =
                            await _masterKeyService.CheckSharesExistAsync(membershipId);

                        if (sharesExistResult.IsErr)
                        {
                            Log.Error(
                                "[LOGOUT-ANONYMOUS] Failed to check master key shares existence for MembershipId: {MembershipId}. Error: {Error}",
                                membershipId, sharesExistResult.UnwrapErr().Message);
                            return Result<AnonymousLogoutResponse, FailureBase>.Ok(new AnonymousLogoutResponse
                            {
                                Result = AnonymousLogoutResponse.Types.Result.SessionNotFound,
                                ServerTimestamp = serverTimestamp,
                                Message = "Session not found"
                            });
                        }

                        bool sharesExist = sharesExistResult.Unwrap();
                        if (!sharesExist)
                        {
                            Log.Warning(
                                "[LOGOUT-ANONYMOUS] No master key shares found for MembershipId: {MembershipId}. Treating as already logged out.",
                                membershipId);
                            return Result<AnonymousLogoutResponse, FailureBase>.Ok(new AnonymousLogoutResponse
                            {
                                Result = AnonymousLogoutResponse.Types.Result.AlreadyLoggedOut,
                                ServerTimestamp = serverTimestamp,
                                Message = "Already logged out"
                            });
                        }

                        Log.Debug("[LOGOUT-ANONYMOUS] Master key shares verified for MembershipId: {MembershipId}",
                            membershipId);

                        Result<Unit, FailureBase> hmacValidation =
                            await ValidateAnonymousLogoutHmacAsync(message, membershipId);
                        if (hmacValidation.IsErr)
                        {
                            Log.Warning("[LOGOUT-ANONYMOUS] HMAC validation failed for MembershipId: {MembershipId}",
                                membershipId);
                            return Result<AnonymousLogoutResponse, FailureBase>.Ok(new AnonymousLogoutResponse
                            {
                                Result = AnonymousLogoutResponse.Types.Result.InvalidHmac,
                                ServerTimestamp = serverTimestamp,
                                Message = "Invalid HMAC proof"
                            });
                        }

                        LogoutReason reason = LogoutReason.UserInitiated;
                        if (!string.IsNullOrEmpty(message.LogoutReason))
                        {
                            if (!Enum.TryParse(message.LogoutReason, true, out reason))
                            {
                                reason = LogoutReason.UserInitiated;
                            }
                        }

                        Guid deviceId = DeviceIdResolver.ResolveDeviceIdFromContext(context);
                        Guid? accountId = message.AccountIdentifier != null && message.AccountIdentifier.Length > 0
                            ? Helpers.FromByteStringToGuid(message.AccountIdentifier)
                            : null;

                        Log.Information(
                            "[LOGOUT-ANONYMOUS] Processing anonymous logout for MembershipId: {MembershipId}, ConnectId: {ConnectId}, DeviceId: {DeviceId}, AccountId: {AccountId}, Reason: {Reason}, Scope: {Scope}",
                            membershipId, connectId, deviceId, accountId, reason, message.Scope);

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
                            Log.Warning(
                                "[LOGOUT-ANONYMOUS] Failed to record logout audit, but continuing with logout: {Error}",
                                auditResult.UnwrapErr().Message);
                        }

                        _ = Task.Run(async () =>
                        {
                            await Task.Delay(2000);
                            _actorSystem.EventStream.Publish(new ProtocolCleanupRequiredEvent(connectId));
                            Log.Information(
                                "[LOGOUT-ANONYMOUS] Protocol cleanup event published for ConnectId: {ConnectId}",
                                connectId);
                        });

                        Log.Information(
                            "[LOGOUT-ANONYMOUS] Anonymous logout completed for ConnectId: {ConnectId}. Protocol cleanup scheduled.",
                            connectId);

                        return Result<AnonymousLogoutResponse, FailureBase>.Ok(new AnonymousLogoutResponse
                        {
                            Result = AnonymousLogoutResponse.Types.Result.Succeeded,
                            ServerTimestamp = serverTimestamp,
                            Message = "Logout successful"
                        });
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
}
