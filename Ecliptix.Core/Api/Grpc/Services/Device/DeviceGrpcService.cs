using Akka.Actor;
using Ecliptix.Core.Api.Grpc.Base;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.SecureEnvelopeHandler;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Device;
using Ecliptix.Protobuf.Protocol;
using Grpc.Core;
using GrpcStatus = Grpc.Core.Status;
using GrpcStatusCode = Grpc.Core.StatusCode;
using Serilog;
using Ecliptix.Core.Api.Grpc;

namespace Ecliptix.Core.Api.Grpc.Services.Device;

public class DeviceGrpcService(
    IGrpcCipherService cipherService,
    IEcliptixActorRegistry actorRegistry)
    : DeviceService.DeviceServiceBase
{
    private readonly EcliptixGrpcServiceBase _baseService = new(cipherService);
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

                return registerResult.Match(
                    response => Result<AppDeviceRegisteredStateReply, FailureBase>.Ok(response),
                    failure => Result<AppDeviceRegisteredStateReply, FailureBase>.Err(failure)
                );
            });
    }

    public override async Task<PubKeyExchange> EstablishSecureChannel(PubKeyExchange request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        BeginAppDeviceEphemeralConnectActorEvent actorEvent = new(request, connectId);

        Result<DeriveSharedSecretReply, EcliptixProtocolFailure> reply =
            await _protocolActor.Ask<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(
                actorEvent, context.CancellationToken);

        if (reply.IsOk)
        {
            return reply.Unwrap().PubKeyExchange;
        }

        EcliptixProtocolFailure failure = reply.UnwrapErr();
        throw new RpcException(failure.ToGrpcStatus());
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