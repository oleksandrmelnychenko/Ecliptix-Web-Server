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
    protected readonly IActorRef AppDevicePersistorActor = actorRegistry.Get(ActorIds.AppDevicePersistorActor);
    protected readonly IActorRef ProtocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);

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
        Console.WriteLine($"[SERVER] ExecuteEncryptedRequest - ConnectionId: {connectionId}, RequestType: {typeof(TRequest).Name}");

        Result<byte[], EcliptixProtocolFailure> decryptResult = await DecryptIncomingPayload<TResponse>(
            encryptedRequest, connectionId, exchangeType, context.CancellationToken);

        if (decryptResult.IsErr)
        {
            Console.WriteLine($"[SERVER] Decryption failed: {decryptResult.UnwrapErr().Message}");
            return await grpcCipherService.CreateFailureResponse<TResponse>(
                decryptResult.UnwrapErr(), connectionId, context);
        }

        Console.WriteLine($"[SERVER] Successfully decrypted incoming payload");
        TRequest parsedRequest = Helpers.ParseFromBytes<TRequest>(decryptResult.Unwrap());

        Result<TResponse, FailureBase> handlerResult =
            await handler(parsedRequest, connectionId, context.CancellationToken);

        if (handlerResult.IsErr)
        {
            Console.WriteLine($"[SERVER] Handler failed: {handlerResult.UnwrapErr().Message}");
            return await grpcCipherService.CreateFailureResponse<TResponse>(
                handlerResult.UnwrapErr(), connectionId, context);
        }

        Console.WriteLine($"[SERVER] Handler succeeded, encrypting response");
        var encryptedResponse = await EncryptOutgoingPayload(
            handlerResult.Unwrap(), connectionId, exchangeType, context);
        Console.WriteLine($"[SERVER] Returning encrypted response - Nonce: {Convert.ToHexString(encryptedResponse.Nonce.ToByteArray())}, Size: {encryptedResponse.Cipher.Length}");
        return encryptedResponse;
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