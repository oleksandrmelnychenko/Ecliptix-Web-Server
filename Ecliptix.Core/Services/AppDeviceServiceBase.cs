using Akka.Actor;
using Akka.Hosting;
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
    ICipherPayloadHandlerFactory cipherPayloadHandlerFactory)
    : AppDeviceServiceActions.AppDeviceServiceActionsBase
{
    protected readonly IActorRef AppDevicePersistorActor = actorRegistry.Get<AppDevicePersistorActor>();
    protected readonly IActorRef ProtocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();
    protected readonly ICipherPayloadHandler CipherPayloadHandler =
        cipherPayloadHandlerFactory.Create<EcliptixProtocolSystemActor>();
    
    protected async Task<TResponse> ExecutePlain<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        Func<TRequest, uint, CancellationToken, Task<Result<TResponse, FailureBase>>> handler)
        where TRequest : class
        where TResponse : class
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);
        var result = await handler(request, connectId, context.CancellationToken);

        if (result.IsOk) return result.Unwrap();
        throw GrpcFailureException.FromDomainFailure(result.UnwrapErr());
    }

    protected async Task<CipherPayload> ExecuteEncrypted<TRequest, TResponse>(
        CipherPayload encryptedRequest,
        ServerCallContext context,
        PubKeyExchangeType exchangeType,
        Func<TRequest, uint, CancellationToken, Task<Result<TResponse, FailureBase>>> handler)
        where TRequest : class, IMessage<TRequest>, new()
        where TResponse : class, IMessage<TResponse>, new()
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        DecryptCipherPayloadActorEvent
            decryptEvent = new DecryptCipherPayloadActorEvent(exchangeType, encryptedRequest);
        ForwardToConnectActorEvent decryptForwarder = new ForwardToConnectActorEvent(connectId, decryptEvent);
        Result<byte[], EcliptixProtocolFailure> decryptResult =
            await ProtocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(decryptForwarder,
                context.CancellationToken);

        if (decryptResult.IsErr)
            return await CipherPayloadHandler.RespondFailure<TResponse>(decryptResult.UnwrapErr(), connectId, context);

        TRequest parsedRequest = Helpers.ParseFromBytes<TRequest>(decryptResult.Unwrap());

        Result<TResponse, FailureBase> handlerResult =
            await handler(parsedRequest, connectId, context.CancellationToken);
        if (handlerResult.IsErr)
            return await CipherPayloadHandler.RespondFailure<TResponse>(handlerResult.UnwrapErr(), connectId, context);

        EncryptPayloadActorEvent encryptCommand =
            new EncryptPayloadActorEvent(exchangeType, handlerResult.Unwrap().ToByteArray());
        
        ForwardToConnectActorEvent encryptForwarder = new ForwardToConnectActorEvent(connectId, encryptCommand);
        Result<CipherPayload, EcliptixProtocolFailure> encryptResult =
            await ProtocolActor.Ask<Result<CipherPayload, EcliptixProtocolFailure>>(encryptForwarder,
                context.CancellationToken);

        return encryptResult.IsOk
            ? encryptResult.Unwrap()
            : await CipherPayloadHandler.RespondFailure<TResponse>(encryptResult.UnwrapErr(), connectId, context);
    }
}