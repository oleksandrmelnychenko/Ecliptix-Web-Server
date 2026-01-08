using System.Buffers;
using System.Security.Cryptography;
using Akka.Actor;
using Serilog;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
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

public sealed class DeviceProvisioningEventRouteProvider : ProtobufEventRouteProvider
{
    private const EventContext DeviceProvisioningContext = EventContext.DeviceProvisioning;

    public DeviceProvisioningEventRouteProvider(IServiceProvider services) : base(services)
    {
        Register(TransportEventType.DeviceProvisioningRegisterDevice, DeviceProvisioningContext,
            SecureEnvelope.Parser, HandleRegisterDevice, idempotencyRequired: true);
        Register(TransportEventType.DeviceProvisioningSecureChannelEstablish, DeviceProvisioningContext,
            SecureEnvelope.Parser, HandleEstablishSecureChannel, idempotencyRequired: true);
        Register(TransportEventType.DeviceProvisioningSecureChannelRestore, DeviceProvisioningContext,
            RestoreChannelRequest.Parser, HandleRestoreSecureChannel, idempotencyRequired: true);
        Register(TransportEventType.DeviceProvisioningSecureChannelAuthEstablish,
            DeviceProvisioningContext,
            AuthenticatedEstablishRequest.Parser, HandleAuthenticatedEstablish, idempotencyRequired: true);
        Register(TransportEventType.DeviceProvisioningGetServerPublicKeys, DeviceProvisioningContext,
            GetServerPublicKeysRequest.Parser, HandleGetServerPublicKeys, idempotencyRequired: false);
    }

    private static async Task<Result<object, FailureBase>> HandleRegisterDevice(
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
        IMasterKeyService masterKeyService = scope.ServiceProvider.GetRequiredService<IMasterKeyService>();
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

                    if (registerResult.IsOk)
                    {
                        return Result<DeviceRegistrationResponse, FailureBase>.Ok(registerResult.Unwrap());
                    }

                    return Result<DeviceRegistrationResponse, FailureBase>.Err(registerResult.UnwrapErr());
                });

        return Result<object, FailureBase>.Ok(response);
    }

    private static async Task<Result<object, FailureBase>> HandleEstablishSecureChannel(
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
            success => Result<object, FailureBase>.Ok(success),
            failure => Result<object, FailureBase>.Err(failure));
    }

    private static async Task<Result<object, FailureBase>> HandleRestoreSecureChannel(
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
                return Result<object, FailureBase>.Ok(new RestoreChannelResponse
                {
                    Status = RestoreChannelResponse.Types.Status.SessionNotFound
                });
            }

            return Result<object, FailureBase>.Ok(new RestoreChannelResponse
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
            return Result<object, FailureBase>.Ok(new RestoreChannelResponse
            {
                Status = RestoreChannelResponse.Types.Status.SessionNotFound
            });
        }

        return Result<object, FailureBase>.Err(failure);
    }

    private static async Task<Result<object, FailureBase>> HandleAuthenticatedEstablish(
        IServiceProvider services,
        AuthenticatedEstablishRequest request,
        EventMetadata metadata,
        CancellationToken cancellationToken)
    {
        uint connectId = GrpcCallContextFactory.ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();

        IMasterKeyService masterKeyService = scope.ServiceProvider.GetRequiredService<IMasterKeyService>();
        IEcliptixActorRegistry actorRegistry = scope.ServiceProvider.GetRequiredService<IEcliptixActorRegistry>();
        IRsaChunkProcessor rsaProcessor = scope.ServiceProvider.GetRequiredService<IRsaChunkProcessor>();
        CertificatePinningService certPinning = scope.ServiceProvider.GetRequiredService<CertificatePinningService>();
        IActorRef protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);

        byte[]? rootKey = null;
        byte[]? masterKeyFingerprint = null;
        byte[]? serverExchangeBuffer = null;

        try
        {
            Guid membershipId = Helpers.FromByteStringToGuid(request.MembershipUniqueId);
            if (request.AccountUniqueId.IsEmpty)
            {
                return Result<object, FailureBase>.Err(
                    MasterKeyFailure.InvalidIdentifier("AccountId is required for authenticated channel setup"));
            }

            Guid accountId = Helpers.FromByteStringToGuid(request.AccountUniqueId);

            Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase> deriveRootResult =
                await masterKeyService.DeriveRootKeyAndFingerprintAsync(accountId);
            if (deriveRootResult.IsErr)
            {
                return Result<object, FailureBase>.Err(deriveRootResult.UnwrapErr());
            }

            (rootKey, masterKeyFingerprint) = deriveRootResult.Unwrap();

            byte[] requestFingerprint = request.MasterKeyFingerprint.ToByteArray();
            if (requestFingerprint.Length != masterKeyFingerprint.Length ||
                !CryptographicOperations.FixedTimeEquals(requestFingerprint, masterKeyFingerprint))
            {
                return Result<object, FailureBase>.Err(MasterKeyFailure.MasterKeyMismatch());
            }

            InitializeProtocolWithMasterKeyActorEvent initEvent = new(
                connectId,
                PubKeyExchange.Parser.ParseFrom(request.ClientPubKeyExchange),
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
                return Result<object, FailureBase>.Err(initResult.UnwrapErr());
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
                return Result<object, FailureBase>.Err(
                    SecureChannelFailure.FromCertificateFailure(encryptResult.UnwrapErr()));
            }

            byte[] encryptedPayload = encryptResult.Unwrap();

            Result<byte[], CertificatePinningFailure> signResult = certPinning.Sign(encryptedPayload.AsMemory());
            if (signResult.IsErr)
            {
                return Result<object, FailureBase>.Err(
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

            return Result<object, FailureBase>.Ok(envelope);
        }
        finally
        {
            if (rootKey != null)
            {
                CryptographicOperations.ZeroMemory(rootKey);
            }

            if (masterKeyFingerprint != null)
            {
                CryptographicOperations.ZeroMemory(masterKeyFingerprint);
            }

            if (serverExchangeBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(serverExchangeBuffer, clearArray: true);
            }
        }
    }

    private static async Task<Result<object, FailureBase>> HandleGetServerPublicKeys(
        IServiceProvider services,
        GetServerPublicKeysRequest request,
        EventMetadata metadata,
        CancellationToken cancellationToken)
    {
        Log.Information("[GetServerPublicKeys] Handler invoked");

        using IServiceScope scope = services.CreateScope();

        uint connectId = GrpcCallContextFactory.ResolveConnectId(metadata);
        IOpaqueKeyRingService opaqueService = scope.ServiceProvider.GetRequiredService<IOpaqueKeyRingService>();
        IEcliptixActorRegistry actorRegistry = scope.ServiceProvider.GetRequiredService<IEcliptixActorRegistry>();
        IActorRef protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);

        Result<byte[], OpaqueServerFailure> serverPublicKeyResult = opaqueService.GetServerPublicKey();
        if (serverPublicKeyResult.IsErr)
        {
            Log.Error("[GetServerPublicKeys] Failed to get server public key: {Error}",
                serverPublicKeyResult.UnwrapErr().Message);
            return Result<object, FailureBase>.Err(
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
            return Result<object, FailureBase>.Err(
                SecureChannelFailure.ProtocolError(
                    $"Failed to get server Kyber public key: {kyberPublicKeyResult.UnwrapErr().Message}"));
        }

        Log.Debug("[GetServerPublicKeys] Got Kyber public key, length: {Length}", kyberPublicKeyResult.Unwrap().Length);

        GetServerPublicKeysResponse response = new()
        {
            ServerPublicKey = ByteString.CopyFrom(serverPublicKeyResult.Unwrap()),
            ServerKyberPublicKey = ByteString.CopyFrom(kyberPublicKeyResult.Unwrap())
        };

        Log.Information(
            "[GetServerPublicKeys] Successfully prepared response with X25519 ({X25519Size} bytes) and Kyber ({KyberSize} bytes) public keys",
            serverPublicKeyResult.Unwrap().Length, kyberPublicKeyResult.Unwrap().Length);

        return Result<object, FailureBase>.Ok(response);
    }

}
