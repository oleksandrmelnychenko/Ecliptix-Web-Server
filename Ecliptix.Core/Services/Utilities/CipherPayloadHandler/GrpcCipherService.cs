using Akka.Actor;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Utilities.CipherPayloadHandler;

public class GrpcCipherService<T>(IEcliptixActorRegistry actorRegistry) : IGrpcCipherService
    where T : ActorBase
{
    private readonly IActorRef _protocolActor = actorRegistry.Get<T>();

    public async Task<Result<CipherPayload, FailureBase>> EncryptPayload(byte[] payload, uint connectId,
        ServerCallContext context)
    {
        EncryptPayloadActorEvent encryptCommand = new(PubKeyExchangeType.DataCenterEphemeralConnect,
            payload);

        ForwardToConnectActorEvent encryptForwarder = new(connectId, encryptCommand);

        Result<CipherPayload, EcliptixProtocolFailure> encryptResult =
            await _protocolActor.Ask<Result<CipherPayload, EcliptixProtocolFailure>>(
                encryptForwarder, context.CancellationToken);

        return encryptResult.Match(
            ok: Result<CipherPayload, FailureBase>.Ok,
            err: Result<CipherPayload, FailureBase>.Err
        );
    }

    public async Task<Result<byte[], FailureBase>> DecryptPayload(CipherPayload request, uint connectId,
        ServerCallContext context)
    {
        DecryptCipherPayloadActorEvent decryptEvent = new(PubKeyExchangeType.DataCenterEphemeralConnect,
            request);

        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptEvent);

        Result<byte[], EcliptixProtocolFailure> decryptionResult =
            await _protocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(decryptForwarder,
                context.CancellationToken);

        return decryptionResult.Match(
            ok: Result<byte[], FailureBase>.Ok,
            err: Result<byte[], FailureBase>.Err
        );
    }

    public async Task<CipherPayload> CreateSuccessResponse<T>(byte[] payload, uint connectId, ServerCallContext context)
        where T : IMessage<T>, new()
    {
        Result<CipherPayload, FailureBase> encryptionResult = await EncryptPayload(payload, connectId, context);

        if (encryptionResult.IsErr)
        {
            return await CreateFailureResponse<T>(encryptionResult.UnwrapErr(), connectId, context);
        }

        return encryptionResult.Unwrap();
    }

    public async Task<CipherPayload> CreateFailureResponse<T>(FailureBase failure, uint connectId,
        ServerCallContext context) where T : IMessage<T>, new()
    {
        context.Status = failure.ToGrpcStatus();
        Result<CipherPayload, FailureBase> encryptResult =
            await EncryptPayload(new T().ToByteArray(), connectId, context);
        if (encryptResult.IsErr)
        {
            return new CipherPayload();
        }

        return encryptResult.Unwrap();
    }

    public async Task<CipherPayload> CreateFailureResponse(FailureBase failure, uint connectId,
        ServerCallContext context)
    {
        context.Status = failure.ToGrpcStatus();
        Result<CipherPayload, FailureBase> encryptResult = await EncryptPayload([], connectId, context);
        return encryptResult.IsErr ? new CipherPayload() : encryptResult.Unwrap();
    }

    public async Task<CipherPayload> ProcessResult<TSuccess, TFailure>(Result<TSuccess, TFailure> result,
        uint connectId, ServerCallContext context)
        where TSuccess : IMessage<TSuccess>, new()
        where TFailure : FailureBase
    {
        return await result.Match(
            async response => await CreateSuccessResponse<TSuccess>(response.ToByteArray(), connectId, context),
            async error => await CreateFailureResponse<TSuccess>(error, connectId, context)
        );
    }
}