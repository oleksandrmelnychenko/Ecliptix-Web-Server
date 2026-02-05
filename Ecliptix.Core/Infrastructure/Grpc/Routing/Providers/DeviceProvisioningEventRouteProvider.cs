using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Akka.Actor;
using Serilog;
using Ecliptix.Core.Infrastructure.Grpc.Security;
using Ecliptix.DeviceProvisioning.Domain.Events;
using Ecliptix.DeviceProvisioning.Domain.Failures;
using Ecliptix.Security.Certificate.Pinning.Crypto;
using Ecliptix.Security.Certificate.Pinning.SecureChannel;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Services;
using Ecliptix.Protobuf.Device;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.Protobuf.Transport.DeviceProvisioning;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel.Grpc;
using Ecliptix.SharedKernel.Grpc.Utilities.CipherPayloadHandler;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Microsoft.Extensions.Options;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Providers;

public static class DeviceProvisioningEventRouteProvider
{
    private const EventContext DeviceProvisioningContext = EventContext.DeviceProvisioning;

    private static ReadOnlySpan<byte> AuthenticatedEstablishProofContext =>
        "Ecliptix.AuthenticatedEstablish.v1"u8;

    [EventRoute(TransportEventType.DeviceRegistration, DeviceProvisioningContext,
        IdempotencyRequired = true)]
    internal static async Task<Result<IMessage, FailureBase>> HandleDeviceRegistration(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken)
    {
        uint connectId = GrpcCallContextFactory.ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();
        GrpcCallContext context = GrpcCallContextFactory.BuildContext(
            metadata, connectId, cancellationToken);

        IGrpcCipherService cipherService = scope.ServiceProvider.GetRequiredService<IGrpcCipherService>();
        IEcliptixActorRegistry actorRegistry = scope.ServiceProvider.GetRequiredService<IEcliptixActorRegistry>();
        IOptions<SecurityConfiguration> securityConfig =
            scope.ServiceProvider.GetRequiredService<IOptions<SecurityConfiguration>>();

        GrpcSecurityService baseService = new(cipherService, securityConfig);
        IActorRef appDevicePersistor = actorRegistry.Get(ActorIds.AppDevicePersistorActor);

        SecureEnvelope response =
            await baseService.ExecuteEncryptedOperationAsync<Device, DeviceRegistrationResponse>(
                envelope, context, async (appDevice, _, _, ct) =>
                {
                    RegisterAppDeviceIfNotExistActorEvent registerEvent =
                        new(appDevice, ct);
                    Task<Result<DeviceRegistrationResponse, AppDeviceFailure>>? registerTask =
                        appDevicePersistor.Ask<Result<DeviceRegistrationResponse, AppDeviceFailure>>(
                            registerEvent, TimeoutConfiguration.Actor.AskTimeout);
                    Result<DeviceRegistrationResponse, AppDeviceFailure> registerResult =
                        await registerTask.WaitAsync(ct).ConfigureAwait(false);

                    return registerResult.IsOk
                        ? Result<DeviceRegistrationResponse, FailureBase>.Ok(registerResult.Unwrap())
                        : Result<DeviceRegistrationResponse, FailureBase>.Err(registerResult.UnwrapErr());
                });

        return Result<IMessage, FailureBase>.Ok(response);
    }

    [EventRoute(TransportEventType.DeviceSessionHandshake, DeviceProvisioningContext,
        IdempotencyRequired = true)]
    internal static async Task<Result<IMessage, FailureBase>> HandleDeviceSessionHandshake(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken)
    {
        uint connectId = GrpcCallContextFactory.ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();

        ISecureChannelEstablisher establisher = scope.ServiceProvider.GetRequiredService<ISecureChannelEstablisher>();
        PubKeyExchangeType exchangeType = ResolveExchangeType(metadata);
        Result<SecureEnvelope, SecureChannelFailure> result = await establisher.EstablishAsync(
            envelope, connectId, exchangeType, cancellationToken);

        return result.Match(
            Result<IMessage, FailureBase>.Ok,
            Result<IMessage, FailureBase>.Err);
    }

    [EventRoute(TransportEventType.DeviceSessionRecovery, DeviceProvisioningContext,
        IdempotencyRequired = true)]
    internal static async Task<Result<IMessage, FailureBase>> HandleDeviceSessionRecovery(
        IServiceProvider services,
        SessionRecoveryRequest request,
        EventMetadata metadata,
        CancellationToken cancellationToken)
    {
        uint connectId = GrpcCallContextFactory.ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();

        IEcliptixActorRegistry actorRegistry = scope.ServiceProvider.GetRequiredService<IEcliptixActorRegistry>();
        IActorRef protocolActor = actorRegistry.Get(ActorIds.EcliptixProtectionProtocolActor);

        RestoreProtocolSessionCommand restoreEvent = new();
        RouteToConnectionCommand forwardEvent = new(connectId, restoreEvent);

        Task<Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>> restoreTask =
            protocolActor.Ask<Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>>(
                forwardEvent, TimeoutConfiguration.Actor.AskTimeout);
        Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure> result =
            await restoreTask.WaitAsync(cancellationToken).ConfigureAwait(false);

        if (result.IsOk)
        {
            RestoreSecrecyChannelResponse protocolResponse = result.Unwrap();
            if (protocolResponse.Status == RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionNotFound)
            {
                return Result<IMessage, FailureBase>.Ok(new SessionRecoveryResponse
                {
                    Result = SessionRecoveryResponse.Types.Result.SessionRecoveryResultNotFound
                });
            }

            return Result<IMessage, FailureBase>.Ok(new SessionRecoveryResponse
            {
                Result = SessionRecoveryResponse.Types.Result.SessionRecoveryResultRestored,
                ReceivingChainIndex = (int)protocolResponse.ReceivingChainLength,
                SendingChainIndex = (int)protocolResponse.SendingChainLength
            });
        }

        EcliptixProtocolFailure failure = result.UnwrapErr();
        if (failure.FailureType == EcliptixProtocolFailureType.ActorRefNotFound ||
            failure.FailureType == EcliptixProtocolFailureType.StateMissing ||
            protocolActor.IsNobody())
        {
            return Result<IMessage, FailureBase>.Ok(new SessionRecoveryResponse
            {
                Result = SessionRecoveryResponse.Types.Result.SessionRecoveryResultNotFound
            });
        }

        return Result<IMessage, FailureBase>.Err(failure);
    }

    [EventRoute(TransportEventType.DeviceSessionAuthHandshake, DeviceProvisioningContext,
        IdempotencyRequired = true, RequiresDeviceId = true, RequiresApplicationInstanceId = true)]
    internal static async Task<Result<IMessage, FailureBase>> HandleDeviceSessionAuthHandshake(
        IServiceProvider services,
        AuthenticatedSessionHandshakeRequest request,
        EventMetadata metadata,
        CancellationToken cancellationToken)
    {
        uint connectId = GrpcCallContextFactory.ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();

        IMasterKeyService masterKeyService = scope.ServiceProvider.GetRequiredService<IMasterKeyService>();
        IEcliptixActorRegistry actorRegistry = scope.ServiceProvider.GetRequiredService<IEcliptixActorRegistry>();
        IReplayProtectionCache replayProtection =
            scope.ServiceProvider.GetRequiredService<IReplayProtectionCache>();
        IServerNonceStore nonceStore = scope.ServiceProvider.GetRequiredService<IServerNonceStore>();
        IRsaChunkProcessor rsaProcessor = scope.ServiceProvider.GetRequiredService<IRsaChunkProcessor>();
        CertificatePinningService certPinning = scope.ServiceProvider.GetRequiredService<CertificatePinningService>();
        IActorRef protocolActor = actorRegistry.Get(ActorIds.EcliptixProtectionProtocolActor);

        byte[]? rootKey = null;
        byte[]? masterKeyFingerprint = null;
        byte[]? serverNonce = null;
        string? replayKey = null;
        bool replayClaimed = false;
        bool success = false;

        try
        {
            Result<AuthenticatedHandshakeContext, FailureBase> validation =
                ValidateAuthenticatedHandshakeRequest(request, metadata, nonceStore, connectId);
            if (validation.IsErr)
            {
                return Result<IMessage, FailureBase>.Err(validation.UnwrapErr());
            }

            AuthenticatedHandshakeContext ctx = validation.Unwrap();
            serverNonce = ctx.ServerNonce;

            Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase> deriveRootResult =
                await masterKeyService.DeriveRootKeyAndFingerprintAsync(ctx.AccountId);
            if (deriveRootResult.IsErr)
            {
                return Result<IMessage, FailureBase>.Err(deriveRootResult.UnwrapErr());
            }

            (rootKey, masterKeyFingerprint) = deriveRootResult.Unwrap();

            ReadOnlySpan<byte> requestFingerprint = ctx.Crypto.MasterKeyFingerprint.Span;
            if (requestFingerprint.Length != masterKeyFingerprint.Length ||
                !CryptographicOperations.FixedTimeEquals(requestFingerprint, masterKeyFingerprint))
            {
                return Result<IMessage, FailureBase>.Err(MasterKeyFailure.MasterKeyMismatch());
            }

            byte[] proofInput = BuildAuthenticatedEstablishProofInput(
                request.Identity!.MembershipId.Span,
                request.Identity.AccountId.Span,
                requestFingerprint,
                ctx.HandshakeInit,
                ctx.Crypto.ClientNonce.Span,
                serverNonce,
                ctx.IdempotencyKey,
                metadata.Client!.DeviceId.ToBase64(),
                metadata.Client.ApplicationInstanceId.ToBase64());

            byte[] expectedProof = HMACSHA256.HashData(rootKey, proofInput);
            ReadOnlySpan<byte> providedProof = ctx.Crypto.Proof.Span;

            if (!CryptographicOperations.FixedTimeEquals(expectedProof, providedProof))
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("Proof verification failed"));
            }

            replayKey = $"{ctx.AccountId:N}:{ctx.IdempotencyKey}";
            replayClaimed = replayProtection.TryBegin(
                DeviceProvisioningConstants.ReplayProtection.AuthenticatedEstablishScope, replayKey, DeviceProvisioningConstants.ReplayProtection.AuthenticatedEstablishTtl);
            if (!replayClaimed)
            {
                return Result<IMessage, FailureBase>.Err(
                    EcliptixProtocolFailure.ReplayAttempt("Authenticated secure channel establish"));
            }

            PubKeyExchangeType exchangeType = ResolveExchangeType(metadata);
            InitializeAuthenticatedSessionCommand initEvent = new(
                connectId,
                exchangeType,
                ctx.HandshakeInit,
                ctx.MembershipId,
                ctx.AccountId);

            RouteToConnectionCommand forwardEvent = new(connectId, initEvent);
            Task<Result<InitializeAuthenticatedSessionResponse, EcliptixProtocolFailure>> initTask =
                protocolActor.Ask<Result<InitializeAuthenticatedSessionResponse, EcliptixProtocolFailure>>(
                    forwardEvent, TimeoutConfiguration.Actor.AskTimeout);
            Result<InitializeAuthenticatedSessionResponse, EcliptixProtocolFailure> initResult =
                await initTask.WaitAsync(cancellationToken).ConfigureAwait(false);

            if (initResult.IsErr)
            {
                return Result<IMessage, FailureBase>.Err(initResult.UnwrapErr());
            }

            InitializeAuthenticatedSessionResponse reply = initResult.Unwrap();
            byte[] handshakeAck = reply.HandshakeAck;

            Result<byte[], CertificatePinningFailure> encryptResult =
                await rsaProcessor.EncryptChunkedAsync(handshakeAck, cancellationToken);
            if (encryptResult.IsErr)
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.FromCertificateFailure(encryptResult.UnwrapErr()));
            }

            byte[] encryptedPayload = encryptResult.Unwrap();

            Result<byte[], CertificatePinningFailure> signResult = certPinning.Sign(encryptedPayload.AsMemory());
            if (signResult.IsErr)
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.FromCertificateFailure(signResult.UnwrapErr()));
            }

            byte[] signature = signResult.Unwrap();

            SecureEnvelope envelope = new()
            {
                Version = 1,
                EncryptedPayload = ByteString.CopyFrom(encryptedPayload),
                EncryptedMetadata = ByteString.CopyFrom(signature),
                HeaderNonce = ByteString.Empty,
                RatchetEpoch = 0,
                SentAt = Timestamp.FromDateTime(DateTime.UtcNow)
            };

            success = true;
            return Result<IMessage, FailureBase>.Ok(envelope);
        }
        finally
        {
            if (replayClaimed && !success && replayKey != null)
            {
                replayProtection.Release(DeviceProvisioningConstants.ReplayProtection.AuthenticatedEstablishScope, replayKey);
            }

            if (rootKey != null)
            {
                CryptographicOperations.ZeroMemory(rootKey);
            }

            if (masterKeyFingerprint != null)
            {
                CryptographicOperations.ZeroMemory(masterKeyFingerprint);
            }

            if (serverNonce != null)
            {
                CryptographicOperations.ZeroMemory(serverNonce);
            }

        }
    }

    [EventRoute(TransportEventType.DeviceServerKeys, DeviceProvisioningContext)]
    internal static async Task<Result<IMessage, FailureBase>> HandleDeviceServerKeys(
        IServiceProvider services,
        ServerPublicKeysRequest _,
        EventMetadata metadata,
        CancellationToken cancellationToken)
    {
        using IServiceScope scope = services.CreateScope();

        uint connectId = GrpcCallContextFactory.ResolveConnectId(metadata);
        IOpaqueKeyRingService opaqueService = scope.ServiceProvider.GetRequiredService<IOpaqueKeyRingService>();
        IEcliptixActorRegistry actorRegistry = scope.ServiceProvider.GetRequiredService<IEcliptixActorRegistry>();
        IServerNonceStore nonceStore = scope.ServiceProvider.GetRequiredService<IServerNonceStore>();
        IActorRef protocolActor = actorRegistry.Get(ActorIds.EcliptixProtectionProtocolActor);

        Result<byte[], OpaqueRelayFailure> relayPublicKeyResult = opaqueService.GetRelayPublicKey();
        if (relayPublicKeyResult.IsErr)
        {
            Log.Error("[GetRelayPublicKeys] Failed to get relay public key: {Error}",
                relayPublicKeyResult.UnwrapErr().Message);
            return Result<IMessage, FailureBase>.Err(
                SecureChannelFailure.ProtocolError(
                    $"Failed to get relay public key: {relayPublicKeyResult.UnwrapErr().Message}"));
        }

        Log.Debug("[GetRelayPublicKeys] Got relay public key, length: {Length}",
            relayPublicKeyResult.Unwrap().Length);

        RouteToConnectionCommand forwardEvent =
            new(connectId, new GetPreKeyBundleQuery());
        Task<Result<byte[], EcliptixProtocolFailure>> bundleTask =
            protocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(
                forwardEvent, TimeoutConfiguration.Actor.AskTimeout);
        Result<byte[], EcliptixProtocolFailure> bundleResult =
            await bundleTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (bundleResult.IsErr)
        {
            Log.Error("[GetRelayPublicKeys] Failed to get relay prekey bundle: {Error}",
                bundleResult.UnwrapErr().Message);
            return Result<IMessage, FailureBase>.Err(
                SecureChannelFailure.ProtocolError(
                    $"Failed to get relay prekey bundle: {bundleResult.UnwrapErr().Message}"));
        }

        Log.Debug("[GetRelayPublicKeys] Got prekey bundle, length: {Length}", bundleResult.Unwrap().Length);

        byte[] relayNonce = RandomNumberGenerator.GetBytes(DeviceProvisioningConstants.Nonce.ServerLength);
        nonceStore.Store(connectId, relayNonce, DeviceProvisioningConstants.ReplayProtection.ServerNonceTtl);

        ServerPublicKeysResponse response = new()
        {
            ServerPublicKey = ByteString.CopyFrom(relayPublicKeyResult.Unwrap()),
            ServerPrekeyBundle = ByteString.CopyFrom(bundleResult.Unwrap()),
            ServerNonce = ByteString.CopyFrom(relayNonce)
        };

        Log.Information(
            "[GetRelayPublicKeys] Successfully prepared response with OPAQUE ({OpaqueSize} bytes) and prekey bundle ({BundleSize} bytes)",
            relayPublicKeyResult.Unwrap().Length, bundleResult.Unwrap().Length);

        return Result<IMessage, FailureBase>.Ok(response);
    }

    private static byte[] BuildAuthenticatedEstablishProofInput(
        ReadOnlySpan<byte> membershipId,
        ReadOnlySpan<byte> accountId,
        ReadOnlySpan<byte> masterKeyFingerprint,
        ReadOnlySpan<byte> handshakeInit,
        ReadOnlySpan<byte> clientNonce,
        ReadOnlySpan<byte> serverNonce,
        string idempotencyKey,
        string appDeviceId,
        string applicationInstanceId)
    {
        const int prefix = 10;

        int idempotencyByteCount = Encoding.UTF8.GetByteCount(idempotencyKey);
        int appDeviceByteCount = Encoding.UTF8.GetByteCount(appDeviceId);
        int appInstanceByteCount = Encoding.UTF8.GetByteCount(applicationInstanceId);

        ReadOnlySpan<byte> context = AuthenticatedEstablishProofContext;
        int totalLength = prefix * sizeof(uint)
                          + context.Length
                          + membershipId.Length
                          + accountId.Length
                          + masterKeyFingerprint.Length
                          + handshakeInit.Length
                          + clientNonce.Length
                          + serverNonce.Length
                          + idempotencyByteCount
                          + appDeviceByteCount
                          + appInstanceByteCount;

        byte[] buffer = new byte[totalLength];
        Span<byte> span = buffer;
        int offset = 0;

        WriteSpanPart(span, ref offset, context);
        WriteSpanPart(span, ref offset, membershipId);
        WriteSpanPart(span, ref offset, accountId);
        WriteSpanPart(span, ref offset, masterKeyFingerprint);
        WriteSpanPart(span, ref offset, handshakeInit);
        WriteSpanPart(span, ref offset, clientNonce);
        WriteSpanPart(span, ref offset, serverNonce);

        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], (uint)idempotencyByteCount);
        offset += sizeof(uint);
        Encoding.UTF8.GetBytes(idempotencyKey, span[offset..]);
        offset += idempotencyByteCount;

        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], (uint)appDeviceByteCount);
        offset += sizeof(uint);
        Encoding.UTF8.GetBytes(appDeviceId, span[offset..]);
        offset += appDeviceByteCount;

        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], (uint)appInstanceByteCount);
        offset += sizeof(uint);
        Encoding.UTF8.GetBytes(applicationInstanceId, span[offset..]);

        return buffer;
    }

    private static void WriteSpanPart(Span<byte> buffer, ref int offset, ReadOnlySpan<byte> part)
    {
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], (uint)part.Length);
        offset += sizeof(uint);
        part.CopyTo(buffer[offset..]);
        offset += part.Length;
    }

    private static Result<AuthenticatedHandshakeContext, FailureBase> ValidateAuthenticatedHandshakeRequest(
        AuthenticatedSessionHandshakeRequest request,
        EventMetadata metadata,
        IServerNonceStore nonceStore,
        uint connectId)
    {
        AuthenticatedSessionHandshakeRequest.Types.Identity? identity = request.Identity;
        AuthenticatedSessionHandshakeRequest.Types.Cryptography? crypto = request.Cryptography;

        if (identity == null || identity.MembershipId.IsEmpty || identity.MembershipId.Length != 16)
        {
            return Result<AuthenticatedHandshakeContext, FailureBase>.Err(
                MasterKeyFailure.InvalidIdentifier("MembershipId is required for authenticated channel setup"));
        }

        if (identity.AccountId.IsEmpty || identity.AccountId.Length != 16)
        {
            return Result<AuthenticatedHandshakeContext, FailureBase>.Err(
                MasterKeyFailure.InvalidIdentifier("AccountId is required for authenticated channel setup"));
        }

        if (crypto == null || crypto.HandshakeInit.IsEmpty)
        {
            return Result<AuthenticatedHandshakeContext, FailureBase>.Err(
                SecureChannelFailure.InvalidPayload("HandshakeInit is required"));
        }

        if (crypto.ClientNonce.Length is < DeviceProvisioningConstants.Nonce.MinLength or > DeviceProvisioningConstants.Nonce.MaxLength)
        {
            return Result<AuthenticatedHandshakeContext, FailureBase>.Err(
                SecureChannelFailure.InvalidPayload("ClientNonce has invalid length"));
        }

        if (crypto.ServerNonce.Length is < DeviceProvisioningConstants.Nonce.MinLength or > DeviceProvisioningConstants.Nonce.MaxLength)
        {
            return Result<AuthenticatedHandshakeContext, FailureBase>.Err(
                SecureChannelFailure.InvalidPayload("ServerNonce has invalid length"));
        }

        if (crypto.Proof.Length != DeviceProvisioningConstants.Proof.Length)
        {
            return Result<AuthenticatedHandshakeContext, FailureBase>.Err(
                SecureChannelFailure.InvalidPayload("Proof has invalid length"));
        }

        ReadOnlySpan<byte> requestServerNonce = crypto.ServerNonce.Span;
        if (!nonceStore.TryTake(connectId, out byte[] serverNonce))
        {
            return Result<AuthenticatedHandshakeContext, FailureBase>.Err(
                SecureChannelFailure.InvalidPayload("ServerNonce is missing or expired"));
        }

        if (requestServerNonce.Length != serverNonce.Length ||
            !CryptographicOperations.FixedTimeEquals(requestServerNonce, serverNonce))
        {
            return Result<AuthenticatedHandshakeContext, FailureBase>.Err(
                SecureChannelFailure.InvalidPayload("ServerNonce mismatch"));
        }

        if (!Helpers.TryFromByteStringToGuid(identity.MembershipId, out Guid membershipId))
        {
            return Result<AuthenticatedHandshakeContext, FailureBase>.Err(
                MasterKeyFailure.InvalidIdentifier("MembershipId is invalid"));
        }

        if (!Helpers.TryFromByteStringToGuid(identity.AccountId, out Guid accountId))
        {
            return Result<AuthenticatedHandshakeContext, FailureBase>.Err(
                MasterKeyFailure.InvalidIdentifier("AccountId is invalid"));
        }

        if (!Helpers.TryParseProto(crypto.HandshakeInit, HandshakeInit.Parser, out HandshakeInit? _))
        {
            return Result<AuthenticatedHandshakeContext, FailureBase>.Err(
                SecureChannelFailure.InvalidPayload("HandshakeInit is invalid"));
        }

        return Result<AuthenticatedHandshakeContext, FailureBase>.Ok(new AuthenticatedHandshakeContext(
            membershipId,
            accountId,
            crypto.HandshakeInit.ToByteArray(),
            serverNonce,
            crypto,
            metadata.Client!.IdempotencyKey));
    }

    private sealed record AuthenticatedHandshakeContext(
        Guid MembershipId,
        Guid AccountId,
        byte[] HandshakeInit,
        byte[] ServerNonce,
        AuthenticatedSessionHandshakeRequest.Types.Cryptography Crypto,
        string IdempotencyKey);

    private static PubKeyExchangeType ResolveExchangeType(EventMetadata metadata)
    {
        string? context = metadata.Security?.KeyExchangeContext;
        if (!string.IsNullOrWhiteSpace(context) &&
            System.Enum.TryParse(context, true, out PubKeyExchangeType exchangeType) &&
            System.Enum.IsDefined(exchangeType))
        {
            return exchangeType;
        }

        return PubKeyExchangeType.DataCenterEphemeralConnect;
    }
}
