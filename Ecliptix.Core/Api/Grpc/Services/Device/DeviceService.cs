using Akka.Actor;
using Ecliptix.Core.Api.Grpc.Base;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Infrastructure.SecureChannel;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Device;
using Ecliptix.Protobuf.Protocol;
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
    INativeOpaqueProtocolService opaqueService)
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
}