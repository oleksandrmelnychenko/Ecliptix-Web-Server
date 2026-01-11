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
    private static readonly byte[] AuthenticatedEstablishProofContext =
        "Ecliptix.AuthenticatedEstablish.v1"u8.ToArray();

    [EventRoute(TransportEventType.DeviceProvisioningRegisterDevice, DeviceProvisioningContext,
        IdempotencyRequired = true)]
    internal static async Task<Result<IMessage, FailureBase>> HandleRegisterDevice(
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
            await baseService.ExecuteEncryptedOperationAsync<AppDevice, DeviceRegistrationResponse>(
                envelope, context, async (appDevice, _, _, ct) =>
                {
                    RegisterAppDeviceIfNotExistActorEvent registerEvent =
                        new(appDevice, metadata.Locale, ct);
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

    [EventRoute(TransportEventType.DeviceProvisioningSecureChannelEstablish, DeviceProvisioningContext,
        IdempotencyRequired = true)]
    internal static async Task<Result<IMessage, FailureBase>> HandleEstablishSecureChannel(
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

    [EventRoute(TransportEventType.DeviceProvisioningSecureChannelRestore, DeviceProvisioningContext,
        IdempotencyRequired = true)]
    internal static async Task<Result<IMessage, FailureBase>> HandleRestoreSecureChannel(
        IServiceProvider services,
        RestoreChannelRequest request,
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
                return Result<IMessage, FailureBase>.Ok(new RestoreChannelResponse
                {
                    Status = RestoreChannelResponse.Types.Status.SessionNotFound
                });
            }

            return Result<IMessage, FailureBase>.Ok(new RestoreChannelResponse
            {
                Status = RestoreChannelResponse.Types.Status.SessionRestored,
                ReceivingChainLength = (int)protocolResponse.ReceivingChainLength,
                SendingChainLength = (int)protocolResponse.SendingChainLength
            });
        }

        EcliptixProtocolFailure failure = result.UnwrapErr();
        if (failure.FailureType == EcliptixProtocolFailureType.ActorRefNotFound ||
            failure.FailureType == EcliptixProtocolFailureType.StateMissing ||
            protocolActor.IsNobody())
        {
            return Result<IMessage, FailureBase>.Ok(new RestoreChannelResponse
            {
                Status = RestoreChannelResponse.Types.Status.SessionNotFound
            });
        }

        return Result<IMessage, FailureBase>.Err(failure);
    }

    [EventRoute(TransportEventType.DeviceProvisioningSecureChannelAuthEstablish, DeviceProvisioningContext,
        IdempotencyRequired = true)]
    internal static async Task<Result<IMessage, FailureBase>> HandleAuthenticatedEstablish(
        IServiceProvider services,
        AuthenticatedEstablishRequest request,
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
            if (string.IsNullOrWhiteSpace(metadata.IdempotencyKey))
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("IdempotencyKey is required for authenticated channel setup"));
            }

            if (string.IsNullOrWhiteSpace(metadata.AppDeviceId) ||
                string.IsNullOrWhiteSpace(metadata.ApplicationInstanceId))
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("AppDeviceId and ApplicationInstanceId are required"));
            }

            if (request.MembershipUniqueId.IsEmpty || request.MembershipUniqueId.Length != 16)
            {
                return Result<IMessage, FailureBase>.Err(
                    MasterKeyFailure.InvalidIdentifier("MembershipId is required for authenticated channel setup"));
            }

            if (request.AccountUniqueId.IsEmpty || request.AccountUniqueId.Length != 16)
            {
                return Result<IMessage, FailureBase>.Err(
                    MasterKeyFailure.InvalidIdentifier("AccountId is required for authenticated channel setup"));
            }

            if (request.ClientPubKeyExchange.IsEmpty)
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("ClientPubKeyExchange is required"));
            }

            if (request.ClientNonce.Length is < MinNonceLength or > MaxNonceLength)
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("ClientNonce has invalid length"));
            }

            if (request.ServerNonce.Length is < MinNonceLength or > MaxNonceLength)
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("ServerNonce has invalid length"));
            }

            if (request.Proof.Length != ProofLength)
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("Proof has invalid length"));
            }

            byte[] requestServerNonce = request.ServerNonce.ToByteArray();
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
                membershipId = Helpers.FromByteStringToGuid(request.MembershipUniqueId);
            }
            catch (Exception ex)
            {
                return Result<IMessage, FailureBase>.Err(
                    MasterKeyFailure.InvalidIdentifier($"MembershipId is invalid: {ex.Message}"));
            }

            Guid accountId;
            try
            {
                accountId = Helpers.FromByteStringToGuid(request.AccountUniqueId);
            }
            catch (Exception ex)
            {
                return Result<IMessage, FailureBase>.Err(
                    MasterKeyFailure.InvalidIdentifier($"AccountId is invalid: {ex.Message}"));
            }

            PubKeyExchange clientExchange;
            try
            {
                clientExchange = PubKeyExchange.Parser.ParseFrom(request.ClientPubKeyExchange);
            }
            catch
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("ClientPubKeyExchange is invalid"));
            }

            Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase> deriveRootResult =
                await masterKeyService.DeriveRootKeyAndFingerprintAsync(accountId);
            if (deriveRootResult.IsErr)
            {
                return Result<IMessage, FailureBase>.Err(deriveRootResult.UnwrapErr());
            }

            (rootKey, masterKeyFingerprint) = deriveRootResult.Unwrap();

            byte[] requestFingerprint = request.MasterKeyFingerprint.ToByteArray();
            if (requestFingerprint.Length != masterKeyFingerprint.Length ||
                !CryptographicOperations.FixedTimeEquals(requestFingerprint, masterKeyFingerprint))
            {
                return Result<IMessage, FailureBase>.Err(MasterKeyFailure.MasterKeyMismatch());
            }

            byte[] membershipIdBytes = request.MembershipUniqueId.ToByteArray();
            byte[] accountIdBytes = request.AccountUniqueId.ToByteArray();
            byte[] clientExchangeBytes = request.ClientPubKeyExchange.ToByteArray();
            byte[] clientNonceBytes = request.ClientNonce.ToByteArray();
            byte[] proofInput = BuildAuthenticatedEstablishProofInput(
                membershipIdBytes,
                accountIdBytes,
                requestFingerprint,
                clientExchangeBytes,
                clientNonceBytes,
                serverNonce!,
                metadata.IdempotencyKey,
                metadata.AppDeviceId,
                metadata.ApplicationInstanceId);
            byte[] expectedProof = HMACSHA256.HashData(rootKey, proofInput);
            byte[] providedProof = request.Proof.ToByteArray();
            if (!CryptographicOperations.FixedTimeEquals(expectedProof, providedProof))
            {
                return Result<IMessage, FailureBase>.Err(
                    SecureChannelFailure.InvalidPayload("Proof verification failed"));
            }

            replayKey = $"{accountId:N}:{metadata.IdempotencyKey}";
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

    [EventRoute(TransportEventType.DeviceProvisioningGetServerPublicKeys, DeviceProvisioningContext)]
    internal static async Task<Result<IMessage, FailureBase>> HandleGetServerPublicKeys(
        IServiceProvider services,
        GetServerPublicKeysRequest _,
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

        GetServerPublicKeysResponse response = new()
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
        byte[] membershipId,
        byte[] accountId,
        byte[] masterKeyFingerprint,
        byte[] clientPubKeyExchange,
        byte[] clientNonce,
        byte[] serverNonce,
        string idempotencyKey,
        string appDeviceId,
        string applicationInstanceId)
    {
        byte[] idempotencyBytes = Encoding.UTF8.GetBytes(idempotencyKey);
        byte[] appDeviceBytes = Encoding.UTF8.GetBytes(appDeviceId);
        byte[] appInstanceBytes = Encoding.UTF8.GetBytes(applicationInstanceId);
        byte[][] parts =
        [
            AuthenticatedEstablishProofContext,
            membershipId,
            accountId,
            masterKeyFingerprint,
            clientPubKeyExchange,
            clientNonce,
            serverNonce,
            idempotencyBytes,
            appDeviceBytes,
            appInstanceBytes
        ];

        int totalLength = 0;
        foreach (byte[] part in parts)
        {
            totalLength += sizeof(uint) + part.Length;
        }

        byte[] buffer = new byte[totalLength];
        int offset = 0;
        foreach (byte[] part in parts)
        {
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset, sizeof(uint)), (uint)part.Length);
            offset += sizeof(uint);
            part.CopyTo(buffer, offset);
            offset += part.Length;
        }

        return buffer;
    }
}
