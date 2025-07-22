using Akka.Actor;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Utilities;

public class CipherPayloadHandler : ICipherPayloadHandler
{
    private readonly IActorRef _protocolActor;
    
    public CipherPayloadHandler(IEcliptixActorRegistry actorRegistry)
    {
        _protocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();
    }
    
    public async Task<Result<CipherPayload, FailureBase>> EncryptResponse(byte[] payload, uint connectId,
        ServerCallContext context)
    {
        EncryptPayloadActorEvent encryptCommand = new(PubKeyExchangeType.DataCenterEphemeralConnect,
            payload);

        ForwardToConnectActorEvent encryptForwarder = new(connectId, encryptCommand);

        Result<CipherPayload, EcliptixProtocolFailure> encryptResult =
            await _protocolActor.Ask<Result<CipherPayload, EcliptixProtocolFailure>>(
                encryptForwarder, context.CancellationToken);

        return encryptResult.Match(
            ok: success => Result<CipherPayload, FailureBase>.Ok(success),
            err: failure => Result<CipherPayload, FailureBase>.Err(failure)
        );
    }
    
    public async Task<Result<byte[], FailureBase>> DecryptRequest(CipherPayload request, uint connectId,
        ServerCallContext context)
    {
        DecryptCipherPayloadActorEvent decryptEvent = new(PubKeyExchangeType.DataCenterEphemeralConnect, 
            request);
        
        ForwardToConnectActorEvent decryptForwarder = new (connectId, decryptEvent);
        
        Result<byte[], EcliptixProtocolFailure> decryptionResult = 
            await _protocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(decryptForwarder,
                context.CancellationToken);

        return decryptionResult.Match(
            ok: success => Result<byte[], FailureBase>.Ok(success),
            err: failure => Result<byte[], FailureBase>.Err(failure)
        );
    }
    
    public async Task<CipherPayload> RespondSuccess<T>(byte[] payload, uint connectId, ServerCallContext context) where T : IMessage<T>, new()
    {
        Result<CipherPayload, FailureBase> encryptionResult = await EncryptResponse(payload, connectId, context);

        if (encryptionResult.IsErr)
        { 
            return await RespondFailure<T>(encryptionResult.UnwrapErr(), connectId, context);
        }
        
        return encryptionResult.Unwrap();
    }
    
    public async Task<CipherPayload> RespondFailure<T>(FailureBase failure, uint connectId, ServerCallContext context) where T : IMessage<T>, new()
    {
        context.Status = failure.ToGrpcStatus();
        Result<CipherPayload, FailureBase> encryptResult = await EncryptResponse(new T().ToByteArray(), connectId, context);
        if (encryptResult.IsErr)
        {
            return new CipherPayload();
        }
        return encryptResult.Unwrap();
    }
    
    public async Task<CipherPayload> HandleResult<TSuccess, TFailure>(Result<TSuccess, TFailure> result, uint connectId, ServerCallContext context)
        where TSuccess : IMessage<TSuccess>, new()
        where TFailure : FailureBase
    {
        return await result.Match(
            async response => await RespondSuccess<TSuccess>(response.ToByteArray(), connectId, context),
            async error => await RespondFailure<TSuccess>(error, connectId, context)
        );
    }
}