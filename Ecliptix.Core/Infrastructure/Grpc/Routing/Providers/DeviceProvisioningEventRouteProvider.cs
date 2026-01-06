using System.Buffers;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using Akka.Actor;
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
using Ecliptix.SecureProtocol.Domain.Protocol;
using Ecliptix.SecureProtocol.Domain.ProtocolNative;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel.Grpc;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Ecliptix.SharedKernel.Grpc.Utilities.CipherPayloadHandler;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Providers;

public sealed class DeviceProvisioningEventRouteProvider : ProtobufEventRouteProvider
{
    public DeviceProvisioningEventRouteProvider(IServiceProvider services) : base(services)
    {
        Register(DeviceProvisioningEventType.DeviceProvisioningRegisterDevice.ToString(), "device_provisioning",
            SecureEnvelope.Parser, HandleRegisterDevice, idempotencyRequired: true);
        Register(DeviceProvisioningEventType.DeviceProvisioningSecureChannelEstablish.ToString(), "device_provisioning",
            SecureEnvelope.Parser, HandleEstablishSecureChannel, idempotencyRequired: true);
        Register(DeviceProvisioningEventType.DeviceProvisioningSecureChannelRestore.ToString(), "device_provisioning",
            RestoreChannelRequest.Parser, HandleRestoreSecureChannel, idempotencyRequired: true);
        Register(DeviceProvisioningEventType.DeviceProvisioningSecureChannelAuthEstablish.ToString(), "device_provisioning",
            AuthenticatedEstablishRequest.Parser, HandleAuthenticatedEstablish, idempotencyRequired: true);
    }

    private static async Task<Result<object, FailureBase>> HandleRegisterDevice(
        IServiceProvider services,
        SecureEnvelope envelope,
        EventMetadata metadata,
        CancellationToken cancellationToken)
    {
        uint connectId = ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();
        GrpcCallContext context = BuildContext(metadata, connectId, cancellationToken);

        IGrpcCipherService cipherService = scope.ServiceProvider.GetRequiredService<IGrpcCipherService>();
        IEcliptixActorRegistry actorRegistry = scope.ServiceProvider.GetRequiredService<IEcliptixActorRegistry>();
        IOpaqueKeyRingService opaqueService = scope.ServiceProvider.GetRequiredService<IOpaqueKeyRingService>();
        IProtocolKeyService protocolKeyService = scope.ServiceProvider.GetRequiredService<IProtocolKeyService>();
        IMasterKeyService masterKeyService = scope.ServiceProvider.GetRequiredService<IMasterKeyService>();
        IOptions<SecurityConfiguration> securityConfig = scope.ServiceProvider.GetRequiredService<IOptions<SecurityConfiguration>>();

        GrpcSecurityService baseService = new GrpcSecurityService(cipherService, securityConfig);
        IActorRef appDevicePersistor = actorRegistry.Get(ActorIds.AppDevicePersistorActor);

        SecureEnvelope response =
            await baseService.ExecuteEncryptedOperationAsync<AppDevice, DeviceRegistrationResponse>(
            envelope, context, async (appDevice, _, _, ct) =>
            {
                RegisterAppDeviceIfNotExistActorEvent registerEvent = new RegisterAppDeviceIfNotExistActorEvent(appDevice, ct);
                Task<Result<DeviceRegistrationResponse, AppDeviceFailure>>? registerTask = appDevicePersistor.Ask<Result<DeviceRegistrationResponse, AppDeviceFailure>>(
                    registerEvent, TimeoutConfiguration.Actor.AskTimeout);
                Result<DeviceRegistrationResponse, AppDeviceFailure> registerResult = await registerTask.WaitAsync(ct).ConfigureAwait(false);

                if (registerResult.IsOk)
                {
                    Result<byte[], OpaqueServerFailure> serverPublicKey = opaqueService.GetServerPublicKey();
                    Result<byte[], EcliptixProtocolFailure> kyberPublicKey = protocolKeyService.GetServerKyberPublicKey();

                    DeviceRegistrationResponse reply = registerResult.Unwrap();
                    reply.ServerPublicKey = ByteString.CopyFrom(serverPublicKey.Unwrap());

                    if (kyberPublicKey.IsOk)
                    {
                        reply.ServerKyberPublicKey = ByteString.CopyFrom(kyberPublicKey.Unwrap());
                    }

                    return Result<DeviceRegistrationResponse, FailureBase>.Ok(reply);
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
        uint connectId = ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();
        GrpcCallContext context = BuildContext(metadata, connectId, cancellationToken);

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
        uint connectId = ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();
        GrpcCallContext context = BuildContext(metadata, connectId, cancellationToken);

        IEcliptixActorRegistry actorRegistry = scope.ServiceProvider.GetRequiredService<IEcliptixActorRegistry>();
        IActorRef protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);

        RestoreAppDeviceSecrecyChannelState restoreEvent = new RestoreAppDeviceSecrecyChannelState();
        ForwardToConnectActorEvent forwardEvent = new ForwardToConnectActorEvent(connectId, restoreEvent);

        Task<Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>> restoreTask = protocolActor.Ask<Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>>(
            forwardEvent, TimeoutConfiguration.Actor.AskTimeout);
        Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure> result = await restoreTask.WaitAsync(cancellationToken).ConfigureAwait(false);

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
        uint connectId = ResolveConnectId(metadata);
        using IServiceScope scope = services.CreateScope();
        GrpcCallContext context = BuildContext(metadata, connectId, cancellationToken);

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

        Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase> deriveRootResult = await masterKeyService.DeriveRootKeyAndFingerprintAsync(accountId);
        if (deriveRootResult.IsErr)
        {
            return Result<object, FailureBase>.Err(deriveRootResult.UnwrapErr());
        }

        (rootKey, masterKeyFingerprint) = deriveRootResult.Unwrap();

        if (rootKey is null || masterKeyFingerprint is null)
        {
            return Result<object, FailureBase>.Err(MasterKeyFailure.InternalError("Root key derivation failed"));
        }

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
            Task<Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>> initTask = protocolActor.Ask<Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>>(
                forwardEvent, TimeoutConfiguration.Actor.AskTimeout);
            Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure> initResult = await initTask.WaitAsync(cancellationToken).ConfigureAwait(false);

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

            Result<byte[], CertificatePinningFailure> encryptResult = await rsaProcessor.EncryptChunkedAsync(serverExchangeMemory, cancellationToken);
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

    private static uint ResolveConnectId(EventMetadata metadata)
    {
        if (metadata.ConnectId != 0)
        {
            return metadata.ConnectId;
        }

        if (uint.TryParse(metadata.PartitionKey, out uint parsed))
        {
            return parsed;
        }

        throw new RpcException(new global::Grpc.Core.Status(StatusCode.InvalidArgument, "connect_id is required"));
    }

    private static GrpcCallContext BuildContext(EventMetadata metadata, uint connectId, CancellationToken cancellationToken)
    {
        Metadata headers = new();
        headers.Add(MetadataConstants.Keys.ConnectId, connectId.ToString(CultureInfo.InvariantCulture));

        // Critical: Copy the connection context ID (exchange type) for encryption to work properly
        if (!string.IsNullOrWhiteSpace(metadata.KeyExchangeContext))
        {
            headers.Add(MetadataConstants.Keys.ConnectionContextId, metadata.KeyExchangeContext);
        }
        else
        {
            // Default to DataCenterEphemeralConnect if not specified
            headers.Add(MetadataConstants.Keys.ConnectionContextId, PubKeyExchangeType.DataCenterEphemeralConnect.ToString());
        }

        if (!string.IsNullOrWhiteSpace(metadata.IdempotencyKey))
        {
            headers.Add(MetadataConstants.Keys.IdempotencyKey, metadata.IdempotencyKey);
        }
        else if (!string.IsNullOrWhiteSpace(metadata.CorrelationId))
        {
            headers.Add(MetadataConstants.Keys.IdempotencyKey, metadata.CorrelationId);
        }

        if (!string.IsNullOrWhiteSpace(metadata.CorrelationId))
        {
            headers.Add(MetadataConstants.Keys.CorrelationId, metadata.CorrelationId);
        }

        if (!string.IsNullOrWhiteSpace(metadata.RequestId))
        {
            headers.Add(MetadataConstants.Keys.RequestId, metadata.RequestId);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Platform))
        {
            headers.Add(MetadataConstants.Keys.Platform, metadata.Platform);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Locale))
        {
            headers.Add(MetadataConstants.Keys.Locale, metadata.Locale);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Version))
        {
            headers.Add(MetadataConstants.Keys.Version, metadata.Version);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Tenant))
        {
            headers.Add(MetadataConstants.Keys.Tenant, metadata.Tenant);
        }

        if (!string.IsNullOrWhiteSpace(metadata.AppDeviceId))
        {
            headers.Add(MetadataConstants.Keys.AppDeviceId, metadata.AppDeviceId);
        }

        if (!string.IsNullOrWhiteSpace(metadata.ApplicationInstanceId))
        {
            headers.Add(MetadataConstants.Keys.ApplicationInstanceId, metadata.ApplicationInstanceId);
        }

        GrpcCallContext ctx = new(metadata.EventType ?? "device_provisioning", "transport", headers, cancellationToken);
        ctx.UserState[GrpcMetadataHandler.UniqueConnectId] = connectId;
        return ctx;
    }
}
