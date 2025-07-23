using Akka.Actor;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Core.Services.Utilities.CipherPayloadHandler;
using Ecliptix.Domain.AppDevices.Persistors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.AppDeviceServices;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services;

public abstract class AppDeviceServiceBase(
    IEcliptixActorRegistry actorRegistry,
    IGrpcCipherService grpcCipherService)
    : AppDeviceServiceActions.AppDeviceServiceActionsBase
{
    protected readonly IActorRef AppDevicePersistorActor = actorRegistry.Get<AppDevicePersistorActor>();
    protected readonly IActorRef ProtocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();

    protected static async Task<TResponse> ExecutePlainRequest<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        Func<TRequest, uint, CancellationToken, Task<Result<TResponse, FailureBase>>> handler)
        where TRequest : class
        where TResponse : class
    {
        uint connectionId = ServiceUtilities.ExtractConnectId(context);
        Result<TResponse, FailureBase> result = await handler(request, connectionId, context.CancellationToken);

        return result.IsOk
            ? result.Unwrap()
            : throw GrpcFailureException.FromDomainFailure(result.UnwrapErr());
    }

    protected async Task<CipherPayload> ExecuteEncryptedRequest<TRequest, TResponse>(
        CipherPayload encryptedRequest,
        ServerCallContext context,
        PubKeyExchangeType exchangeType,
        Func<TRequest, uint, CancellationToken, Task<Result<TResponse, FailureBase>>> handler)
        where TRequest : class, IMessage<TRequest>, new()
        where TResponse : class, IMessage<TResponse>, new()
    {
        uint connectionId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], EcliptixProtocolFailure> decryptResult = await DecryptIncomingPayload<TResponse>(
            encryptedRequest, connectionId, exchangeType, context.CancellationToken);

        if (decryptResult.IsErr)
            return await grpcCipherService.CreateFailureResponse<TResponse>(
                decryptResult.UnwrapErr(), connectionId, context);

        TRequest parsedRequest = Helpers.ParseFromBytes<TRequest>(decryptResult.Unwrap());

        Result<TResponse, FailureBase> handlerResult =
            await handler(parsedRequest, connectionId, context.CancellationToken);

        if (handlerResult.IsErr)
            return await grpcCipherService.CreateFailureResponse<TResponse>(
                handlerResult.UnwrapErr(), connectionId, context);

        return await EncryptOutgoingPayload(
            handlerResult.Unwrap(), connectionId, exchangeType, context);
    }

    private async Task<Result<byte[], EcliptixProtocolFailure>> DecryptIncomingPayload<TResponse>(
        CipherPayload encryptedPayload,
        uint connectionId,
        PubKeyExchangeType exchangeType,
        CancellationToken cancellationToken)
        where TResponse : class, IMessage<TResponse>, new()
    {
        DecryptCipherPayloadActorEvent decryptEvent = new(exchangeType, encryptedPayload);
        ForwardToConnectActorEvent forwardEvent = new(connectionId, decryptEvent);

        return await ProtocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(
            forwardEvent, cancellationToken);
    }

    private async Task<CipherPayload> EncryptOutgoingPayload<TResponse>(
        TResponse response,
        uint connectionId,
        PubKeyExchangeType exchangeType,
        ServerCallContext context)
        where TResponse : class, IMessage<TResponse>, new()
    {
        EncryptPayloadActorEvent encryptEvent = new(exchangeType, response.ToByteArray());
        ForwardToConnectActorEvent forwardEvent = new(connectionId, encryptEvent);

        Result<CipherPayload, EcliptixProtocolFailure> encryptResult =
            await ProtocolActor.Ask<Result<CipherPayload, EcliptixProtocolFailure>>(
                forwardEvent, context.CancellationToken);

        return encryptResult.IsOk
            ? encryptResult.Unwrap()
            : await grpcCipherService.CreateFailureResponse<TResponse>(
                encryptResult.UnwrapErr(), connectionId, context);
    }
}