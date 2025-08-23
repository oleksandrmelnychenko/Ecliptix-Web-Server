using Akka.Actor;
using Ecliptix.Core.Api.Grpc.Base;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
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

namespace Ecliptix.Core.Api.Grpc.Services.Device;

public class DeviceGrpcService(
    IGrpcCipherService cipherService,
    IEcliptixActorRegistry actorRegistry)
    : DeviceService.DeviceServiceBase
{
    private readonly EcliptixGrpcServiceBase _baseService = new(cipherService);
    private readonly IActorRef _protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);
    private readonly IActorRef _appDevicePersistorActor = actorRegistry.Get(ActorIds.AppDevicePersistorActor);

    public override async Task<CipherPayload> RegisterDevice(CipherPayload request, ServerCallContext context)
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

        try
        {
            BeginAppDeviceEphemeralConnectActorEvent actorEvent = new(request, connectId);

            Result<DeriveSharedSecretReply, EcliptixProtocolFailure> reply =
                await _protocolActor.Ask<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(
                    actorEvent, context.CancellationToken);

            if (reply.IsOk)
            {
                return reply.Unwrap().PubKeyExchange;
            }

            EcliptixProtocolFailure failure = reply.UnwrapErr();
            Log.Error("Failed to establish secure channel for connect ID {ConnectId}: {Message}",
                connectId, failure.Message);

            throw new RpcException(failure.ToGrpcStatus());
        }
        catch (Exception ex) when (ex is not RpcException)
        {
            Log.Error(ex, "Error in EstablishSecureChannel for connect ID {ConnectId}", connectId);
            throw new RpcException(new GrpcStatus(GrpcStatusCode.Internal, "Internal server error"));
        }
    }

    public override async Task<RestoreChannelResponse> RestoreSecureChannel(RestoreChannelRequest request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        try
        {
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

                return new RestoreChannelResponse()
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
                Log.Information("Session not found for connect ID {ConnectId}, returning not found status",
                    connectId);
                return new RestoreChannelResponse
                {
                    Status = RestoreChannelResponse.Types.Status.SessionNotFound
                };
            }

            Log.Error("Failed to restore secure channel for connect ID {ConnectId}: {Message}",
                connectId, failure.Message);

            throw new RpcException(failure.ToGrpcStatus());
        }
        catch (Exception ex) when (ex is not RpcException)
        {
            Log.Error(ex, "Error in RestoreSecureChannel for connect ID {ConnectId}", connectId);
            throw new RpcException(new GrpcStatus(GrpcStatusCode.Internal, "Internal server error"));
        }
    }
}