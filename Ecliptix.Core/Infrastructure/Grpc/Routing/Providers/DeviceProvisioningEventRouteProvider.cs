using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Akka.Actor;
using Serilog;
using Ecliptix.Core.Infrastructure.Grpc.Security;
using Ecliptix.DeviceProvisioning.Domain.Events;
using Ecliptix.DeviceProvisioning.Domain.Failures;
using Ecliptix.DeviceProvisioning.Infrastructure.Crypto;
using Ecliptix.DeviceProvisioning.Infrastructure.SecureChannel;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Services.Security;
using Ecliptix.Protobuf.Common;
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
using Microsoft.Extensions.Options;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Providers;

public static class DeviceProvisioningEventRouteProvider
{
    private const EventContext DeviceProvisioningContext = EventContext.DeviceProvisioning;
    private const int ProofLength = 32;
    private const int MinNonceLength = 16;
    private const int MaxNonceLength = 64;
    private const int ServerNonceLength = 32;
    private const string AuthenticatedEstablishReplayScope = "device_provisioning.auth_establish";
    private static readonly TimeSpan AuthenticatedEstablishReplayTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ServerNonceTtl = TimeSpan.FromMinutes(5);

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
        Result<SecureEnvelope, SecureChannelFailure> result = await establisher.EstablishAsync(
            envelope, connectId, cancellationToken);

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
        IActorRef protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);

        RestoreAppDeviceSecrecyChannelState restoreEvent = new();
        ForwardToConnectActorEvent forwardEvent = new(connectId, restoreEvent);

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
        IdempotencyRequired = true)]
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
        IActorRef protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);

        byte[]? rootKey = null;
        byte[]? masterKeyFingerprint = null;
        byte[]? serverNonce = null;
        byte[]? serverExchangeBuffer = null;
        string? replayKey = null;
        bool replayClaimed = false;
        bool success = false;

        try
        {
            if (string.IsNullOrWhiteSpace(metadata.Client?.IdempotencyKey))
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("IdempotencyKey is required for authenticated channel setup"));
            }

            if (metadata.Client?.DeviceId == null || metadata.Client.DeviceId.IsEmpty ||
                metadata.Client?.ApplicationInstanceId == null || metadata.Client.ApplicationInstanceId.IsEmpty)
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("DeviceId and ApplicationInstanceId are required"));
            }

            AuthenticatedSessionHandshakeRequest.Types.Identity? identity = request.Identity;
            AuthenticatedSessionHandshakeRequest.Types.Cryptography? crypto = request.Cryptography;

            if (identity == null || identity.MembershipId.IsEmpty || identity.MembershipId.Length != 16)
            {
                return Result<IMessage, FailureBase>.Err(
                    MasterKeyFailure.InvalidIdentifier("MembershipId is required for authenticated channel setup"));
            }

            if (identity.AccountId.IsEmpty || identity.AccountId.Length != 16)
            {
                return Result<IMessage, FailureBase>.Err(
                    MasterKeyFailure.InvalidIdentifier("AccountId is required for authenticated channel setup"));
            }

            if (crypto == null || crypto.PubKeyExchange.IsEmpty)
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("PubKeyExchange is required"));
            }

            if (crypto.ClientNonce.Length is < MinNonceLength or > MaxNonceLength)
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("ClientNonce has invalid length"));
            }

            if (crypto.ServerNonce.Length is < MinNonceLength or > MaxNonceLength)
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("ServerNonce has invalid length"));
            }

            if (crypto.Proof.Length != ProofLength)
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("Proof has invalid length"));
            }

            ReadOnlySpan<byte> requestServerNonce = crypto.ServerNonce.Span;
            if (!nonceStore.TryTake(connectId, out serverNonce))
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("ServerNonce is missing or expired"));
            }

            if (requestServerNonce.Length != serverNonce.Length ||
                !CryptographicOperations.FixedTimeEquals(requestServerNonce, serverNonce))
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("ServerNonce mismatch"));
            }

            Guid membershipId;
            try
            {
                membershipId = Helpers.FromByteStringToGuid(identity.MembershipId);
            }
            catch (Exception ex)
            {
                return Result<IMessage, FailureBase>.Err(
                    MasterKeyFailure.InvalidIdentifier($"MembershipId is invalid: {ex.Message}"));
            }

            Guid accountId;
            try
            {
                accountId = Helpers.FromByteStringToGuid(identity.AccountId);
            }
            catch (Exception ex)
            {
                return Result<IMessage, FailureBase>.Err(
                    MasterKeyFailure.InvalidIdentifier($"AccountId is invalid: {ex.Message}"));
            }

            PubKeyExchange clientExchange;
            try
            {
                clientExchange = PubKeyExchange.Parser.ParseFrom(crypto.PubKeyExchange);
            }
            catch
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("PubKeyExchange is invalid"));
            }

            Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase> deriveRootResult =
                await masterKeyService.DeriveRootKeyAndFingerprintAsync(accountId);
            if (deriveRootResult.IsErr)
            {
                return Result<IMessage, FailureBase>.Err(deriveRootResult.UnwrapErr());
            }

            (rootKey, masterKeyFingerprint) = deriveRootResult.Unwrap();

            ReadOnlySpan<byte> requestFingerprint = crypto.MasterKeyFingerprint.Span;
            if (requestFingerprint.Length != masterKeyFingerprint.Length ||
                !CryptographicOperations.FixedTimeEquals(requestFingerprint, masterKeyFingerprint))
            {
                return Result<IMessage, FailureBase>.Err(MasterKeyFailure.MasterKeyMismatch());
            }

            byte[] proofInput = BuildAuthenticatedEstablishProofInput(
                identity.MembershipId.Span,
                identity.AccountId.Span,
                requestFingerprint,
                crypto.PubKeyExchange.Span,
                crypto.ClientNonce.Span,
                serverNonce!,
                metadata.Client!.IdempotencyKey,
                metadata.Client.DeviceId.ToBase64(),
                metadata.Client.ApplicationInstanceId.ToBase64());
            byte[] expectedProof = HMACSHA256.HashData(rootKey, proofInput);
            ReadOnlySpan<byte> providedProof = crypto.Proof.Span;
            if (!CryptographicOperations.FixedTimeEquals(expectedProof, providedProof))
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("Proof verification failed"));
            }

            replayKey = $"{accountId:N}:{metadata.Client.IdempotencyKey}";
            replayClaimed = replayProtection.TryBegin(
                AuthenticatedEstablishReplayScope, replayKey, AuthenticatedEstablishReplayTtl);
            if (!replayClaimed)
            {
                return Result<IMessage, FailureBase>.Err(
                    EcliptixProtocolFailure.ReplayAttempt("Authenticated secure channel establish"));
            }

            InitializeProtocolWithMasterKeyActorEvent initEvent = new(
                connectId,
                clientExchange,
                membershipId,
                accountId,
                rootKey);

            ForwardToConnectActorEvent forwardEvent = new(connectId, initEvent);
            Task<Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>> initTask =
                protocolActor.Ask<Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>>(
                    forwardEvent, TimeoutConfiguration.Actor.AskTimeout);
            Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure> initResult =
                await initTask.WaitAsync(cancellationToken).ConfigureAwait(false);

            if (initResult.IsErr)
            {
                return Result<IMessage, FailureBase>.Err(initResult.UnwrapErr());
            }

            InitializeProtocolWithMasterKeyReply reply = initResult.Unwrap();
            int serverExchangeSize = reply.ServerPubKeyExchange.CalculateSize();
            ReadOnlyMemory<byte> serverExchangeMemory = ReadOnlyMemory<byte>.Empty;
            if (serverExchangeSize > 0)
            {
                serverExchangeBuffer = ArrayPool<byte>.Shared.Rent(serverExchangeSize);
                using MemoryStream stream = new(serverExchangeBuffer, 0, serverExchangeSize, writable: true,
                    publiclyVisible: true);
                using CodedOutputStream output = new(stream, leaveOpen: true);
                reply.ServerPubKeyExchange.WriteTo(output);
                output.Flush();
                serverExchangeMemory = new ReadOnlyMemory<byte>(serverExchangeBuffer, 0, serverExchangeSize);
            }

            Result<byte[], CertificatePinningFailure> encryptResult =
                await rsaProcessor.EncryptChunkedAsync(serverExchangeMemory, cancellationToken);
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
                EncryptedPayload = ByteString.CopyFrom(encryptedPayload),
                AuthenticationTag = ByteString.CopyFrom(signature),
                MetaData = ByteString.Empty,
                ResultCode = ByteString.Empty
            };

            success = true;
            return Result<IMessage, FailureBase>.Ok(envelope);
        }
        finally
        {
            if (replayClaimed && !success && replayKey != null)
            {
                replayProtection.Release(AuthenticatedEstablishReplayScope, replayKey);
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

            if (serverExchangeBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(serverExchangeBuffer, clearArray: true);
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
        IActorRef protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);

        Result<byte[], OpaqueServerFailure> serverPublicKeyResult = opaqueService.GetServerPublicKey();
        if (serverPublicKeyResult.IsErr)
        {
            Log.Error("[GetServerPublicKeys] Failed to get server public key: {Error}",
                serverPublicKeyResult.UnwrapErr().Message);
            return Result<IMessage, FailureBase>.Err(
                SecureChannelFailure.ProtocolError(
                    $"Failed to get server public key: {serverPublicKeyResult.UnwrapErr().Message}"));
        }

        Log.Debug("[GetServerPublicKeys] Got server public key, length: {Length}",
            serverPublicKeyResult.Unwrap().Length);

        ForwardToConnectActorEvent forwardEvent =
            new(connectId, new GetConnectionKyberPublicKeyActorEvent());
        Task<Result<byte[], EcliptixProtocolFailure>> kyberTask =
            protocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(
                forwardEvent, TimeoutConfiguration.Actor.AskTimeout);
        Result<byte[], EcliptixProtocolFailure> kyberPublicKeyResult =
            await kyberTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (kyberPublicKeyResult.IsErr)
        {
            Log.Error("[GetServerPublicKeys] Failed to get server Kyber public key: {Error}",
                kyberPublicKeyResult.UnwrapErr().Message);
            return Result<IMessage, FailureBase>.Err(
                SecureChannelFailure.ProtocolError(
                    $"Failed to get server Kyber public key: {kyberPublicKeyResult.UnwrapErr().Message}"));
        }

        Log.Debug("[GetServerPublicKeys] Got Kyber public key, length: {Length}", kyberPublicKeyResult.Unwrap().Length);

        byte[] serverNonce = RandomNumberGenerator.GetBytes(ServerNonceLength);
        nonceStore.Store(connectId, serverNonce, ServerNonceTtl);

        ServerPublicKeysResponse response = new()
        {
            ServerPublicKey = ByteString.CopyFrom(serverPublicKeyResult.Unwrap()),
            ServerKyberPublicKey = ByteString.CopyFrom(kyberPublicKeyResult.Unwrap()),
            ServerNonce = ByteString.CopyFrom(serverNonce)
        };

        Log.Information(
            "[GetServerPublicKeys] Successfully prepared response with X25519 ({X25519Size} bytes) and Kyber ({KyberSize} bytes) public keys",
            serverPublicKeyResult.Unwrap().Length, kyberPublicKeyResult.Unwrap().Length);

        return Result<IMessage, FailureBase>.Ok(response);
    }

    private static byte[] BuildAuthenticatedEstablishProofInput(
        ReadOnlySpan<byte> membershipId,
        ReadOnlySpan<byte> accountId,
        ReadOnlySpan<byte> masterKeyFingerprint,
        ReadOnlySpan<byte> clientPubKeyExchange,
        ReadOnlySpan<byte> clientNonce,
        ReadOnlySpan<byte> serverNonce,
        string idempotencyKey,
        string appDeviceId,
        string applicationInstanceId)
    {
        int idempotencyByteCount = Encoding.UTF8.GetByteCount(idempotencyKey);
        int appDeviceByteCount = Encoding.UTF8.GetByteCount(appDeviceId);
        int appInstanceByteCount = Encoding.UTF8.GetByteCount(applicationInstanceId);

        ReadOnlySpan<byte> context = AuthenticatedEstablishProofContext;
        int totalLength = 10 * sizeof(uint) // 10 length prefixes
                          + context.Length
                          + membershipId.Length
                          + accountId.Length
                          + masterKeyFingerprint.Length
                          + clientPubKeyExchange.Length
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
        WriteSpanPart(span, ref offset, clientPubKeyExchange);
        WriteSpanPart(span, ref offset, clientNonce);
        WriteSpanPart(span, ref offset, serverNonce);

        // Write UTF8 strings directly to buffer
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
}
