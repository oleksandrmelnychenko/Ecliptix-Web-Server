using Akka.Actor;
using Ecliptix.Core.Api.Grpc.Base;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Infrastructure.Crypto;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Infrastructure.SecureChannel;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.Services.Security;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Device;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Services;
using Ecliptix.Utilities;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Api.Grpc.Services.Device;

public class DeviceService(
    IGrpcCipherService cipherService,
    IEcliptixActorRegistry actorRegistry,
    ISecureChannelEstablisher secureChannelEstablisher,
    INativeOpaqueProtocolService opaqueService,
    IMasterKeyService masterKeyService,
    IRsaChunkProcessor rsaChunkProcessor,
    CertificatePinningService certificatePinningService)
    : Protobuf.Device.DeviceService.DeviceServiceBase
{
    private readonly RpcServiceBase _baseService = new(cipherService);
    private readonly IActorRef _protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);
    private readonly IActorRef _appDevicePersistorActor = actorRegistry.Get(ActorIds.AppDevicePersistorActor);

    public override async Task<SecureEnvelope> RegisterDevice(SecureEnvelope request, ServerCallContext context)
    {
        return await _baseService.ExecuteEncryptedOperationAsync<AppDevice, AppDeviceRegisteredStateReply>(
            request, context, async (appDevice, _, cancellationToken) =>
            {
                RegisterAppDeviceIfNotExistActorEvent registerEvent = new(appDevice);
                Result<AppDeviceRegisteredStateReply, AppDeviceFailure> registerResult =
                    await _appDevicePersistorActor.Ask<Result<AppDeviceRegisteredStateReply, AppDeviceFailure>>(
                        registerEvent, cancellationToken);

                if (registerResult.IsOk)
                {
                    Result<byte[], OpaqueServerFailure> serverPublicKey =
                        ((OpaqueProtocolService)opaqueService).GetServerPublicKey();

                    AppDeviceRegisteredStateReply reply = registerResult.Unwrap();
                    reply.ServerPublicKey = ByteString.CopyFrom(serverPublicKey.Unwrap());

                    return Result<AppDeviceRegisteredStateReply, FailureBase>.Ok(reply);
                }

                return Result<AppDeviceRegisteredStateReply, FailureBase>.Err(registerResult.UnwrapErr());
            });
    }

    public override async Task<SecureEnvelope> EstablishSecureChannel(SecureEnvelope request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<SecureEnvelope, SecureChannelFailure> result = await secureChannelEstablisher.EstablishAsync(
            request,
            connectId,
            context.CancellationToken);

        return result.Match(
            success => success,
            failure => throw failure.ToRpcException());
    }

    public override async Task<RestoreChannelResponse> RestoreSecureChannel(RestoreChannelRequest request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        RestoreAppDeviceSecrecyChannelState restoreEvent = new();
        ForwardToConnectActorEvent forwardEvent = new(connectId, restoreEvent);

        Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure> result =
            await _protocolActor.Ask<Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>>(
                forwardEvent, context.CancellationToken);

        if (result.IsOk)
        {
            RestoreSecrecyChannelResponse protocolResponse = result.Unwrap();
            if (protocolResponse.Status == RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionNotFound)
            {
                return new RestoreChannelResponse
                {
                    Status = RestoreChannelResponse.Types.Status.SessionNotFound,
                };
            }

            return new RestoreChannelResponse
            {
                Status = RestoreChannelResponse.Types.Status.SessionRestored,
                ReceivingChainLength = protocolResponse.ReceivingChainLength,
                SendingChainLength = protocolResponse.SendingChainLength
            };
        }

        EcliptixProtocolFailure failure = result.UnwrapErr();

        if (failure.FailureType == EcliptixProtocolFailureType.ActorRefNotFound ||
            failure.FailureType == EcliptixProtocolFailureType.StateMissing ||
            _protocolActor.IsNobody())
        {
            return new RestoreChannelResponse
            {
                Status = RestoreChannelResponse.Types.Status.SessionNotFound
            };
        }

        throw new RpcException(failure.ToGrpcStatus());
    }

    public override async Task<SecureEnvelope> AuthenticatedEstablishSecureChannel(
        AuthenticatedEstablishRequest request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        // Parse membership GUID from bytes
        Guid membershipId = new Guid(request.MembershipUniqueId.ToByteArray());

        // Derive deterministic identity keys from master key
        Result<dynamic, FailureBase> deriveKeysResult = await masterKeyService.DeriveIdentityKeysAsync(membershipId);

        if (deriveKeysResult.IsErr)
        {
            FailureBase failure = deriveKeysResult.UnwrapErr();
            throw new RpcException(new global::Grpc.Core.Status(StatusCode.Internal,
                $"Failed to derive identity keys: {failure.Message}"));
        }

        EcliptixSystemIdentityKeys identityKeys = (EcliptixSystemIdentityKeys)deriveKeysResult.Unwrap();

        // Initialize protocol with derived identity keys and perform X3DH handshake
        InitializeProtocolWithMasterKeyActorEvent initEvent = new(
            connectId,
            identityKeys,
            request.ClientPubKeyExchange,
            membershipId);

        ForwardToConnectActorEvent forwardEvent = new(connectId, initEvent);

        Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure> initResult =
            await _protocolActor.Ask<Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>>(
                forwardEvent, context.CancellationToken);

        if (initResult.IsErr)
        {
            EcliptixProtocolFailure failure = initResult.UnwrapErr();
            identityKeys.Dispose(); // Clean up on failure
            throw new RpcException(new global::Grpc.Core.Status(StatusCode.Internal,
                $"Failed to initialize authenticated protocol: {failure.Message}"));
        }

        InitializeProtocolWithMasterKeyReply reply = initResult.Unwrap();

        // Serialize server's public key exchange
        byte[] serverExchangeBytes = reply.ServerPubKeyExchange.ToByteArray();

        // RSA-encrypt the server's public key exchange
        Result<byte[], CertificatePinningFailure> encryptResult =
            await rsaChunkProcessor.EncryptChunkedAsync(serverExchangeBytes, context.CancellationToken);

        if (encryptResult.IsErr)
        {
            CertificatePinningFailure encryptFailure = encryptResult.UnwrapErr();
            throw new RpcException(new global::Grpc.Core.Status(StatusCode.Internal,
                $"Failed to RSA encrypt server exchange: {encryptFailure.Message}"));
        }

        byte[] encryptedPayload = encryptResult.Unwrap();

        // Sign the encrypted payload
        Result<byte[], CertificatePinningFailure> signResult =
            certificatePinningService.Sign(encryptedPayload.AsMemory());

        if (signResult.IsErr)
        {
            CertificatePinningFailure signFailure = signResult.UnwrapErr();
            throw new RpcException(new global::Grpc.Core.Status(StatusCode.Internal,
                $"Failed to sign encrypted payload: {signFailure.Message}"));
        }

        byte[] signature = signResult.Unwrap();

        // Return encrypted and signed response
        return new SecureEnvelope
        {
            EncryptedPayload = ByteString.CopyFrom(encryptedPayload),
            AuthenticationTag = ByteString.CopyFrom(signature),
            MetaData = ByteString.Empty,
            ResultCode = ByteString.Empty
        };
    }
}