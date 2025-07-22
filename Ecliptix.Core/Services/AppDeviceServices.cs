using Akka.Actor;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services.Utilities.CipherPayloadHandler;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.AppDevice;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Grpc.Core;

namespace Ecliptix.Core.Services;

public class AppDeviceServices(
    IEcliptixActorRegistry actorRegistry,
    ICipherPayloadHandler cipherPayloadHandler)
    : AppDeviceServiceBase(actorRegistry, cipherPayloadHandler)
{
    public override async Task<RestoreSecrecyChannelResponse> RestoreAppDeviceSecrecyChannel(
        RestoreSecrecyChannelRequest request, ServerCallContext context)
    {
        return await ExecutePlain<RestoreSecrecyChannelRequest, RestoreSecrecyChannelResponse>(
            request,
            context,
            async (_, connectId, ct) =>
            {
                ForwardToConnectActorEvent forwardEvent = new ForwardToConnectActorEvent(connectId, new RestoreAppDeviceSecrecyChannelState());
                Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure> restoreResult =
                    await ProtocolActor
                        .Ask<Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>>(forwardEvent, ct);

                if (restoreResult.IsErr)
                {
                    var failure = restoreResult.UnwrapErr();
                    if (failure.FailureType == EcliptixProtocolFailureType.ActorRefNotFound || ProtocolActor.IsNobody())
                    {
                        return Result<RestoreSecrecyChannelResponse, FailureBase>.Ok(new RestoreSecrecyChannelResponse
                        {
                            Status = RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionNotFound
                        });
                    }

                    return Result<RestoreSecrecyChannelResponse, FailureBase>.Err(failure);
                }

                return Result<RestoreSecrecyChannelResponse, FailureBase>.Ok(restoreResult.Unwrap());
            });
    }

    public override async Task<PubKeyExchange> EstablishAppDeviceSecrecyChannel(
        PubKeyExchange request, ServerCallContext context)
    {
        return await ExecutePlain<PubKeyExchange, PubKeyExchange>(
            request,
            context,
            async (parsedRequest, connectId, ct) =>
            {
                BeginAppDeviceEphemeralConnectActorEvent actorEvent =
                    new BeginAppDeviceEphemeralConnectActorEvent(parsedRequest, connectId);
                
                Result<DeriveSharedSecretReply, EcliptixProtocolFailure> reply =
                    await ProtocolActor.Ask<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(actorEvent, ct);

                return reply.IsOk
                    ? Result<PubKeyExchange, FailureBase>.Ok(reply.Unwrap().PubKeyExchange)
                    : Result<PubKeyExchange, FailureBase>.Err(reply.UnwrapErr());
            });
    }


    public override async Task<CipherPayload> RegisterDeviceAppIfNotExist(
        CipherPayload request, ServerCallContext context)
    {
        return await ExecuteEncrypted<AppDevice, AppDeviceRegisteredStateReply>(
            request,
            context,
            PubKeyExchangeType.DataCenterEphemeralConnect,
            async (appDevice, _ ,ct) =>
            {
                var registerResult = await AppDevicePersistorActor.Ask<Result<AppDeviceRegisteredStateReply, AppDeviceFailure>>(
                    new RegisterAppDeviceIfNotExistActorEvent(appDevice), ct);

                return registerResult.IsOk
                    ? Result<AppDeviceRegisteredStateReply, FailureBase>.Ok(registerResult.Unwrap())
                    : Result<AppDeviceRegisteredStateReply, FailureBase>.Err(registerResult.UnwrapErr());
            });
    }
}