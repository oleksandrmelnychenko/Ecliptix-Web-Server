using Akka.Actor;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Google.Protobuf;
using Grpc.Core;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;

public class GrpcCipherService<T>(IEcliptixActorRegistry actorRegistry) : IGrpcCipherService
    where T : ActorBase
{
    private readonly IActorRef _protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);

    private static PubKeyExchangeType DetermineExchangeType(ServerCallContext context)
    {
        string methodName = context.Method;

        return methodName switch
        {
            string method when method.Contains("InitiateVerification") => PubKeyExchangeType.VerificationFlowStream,
            string method when method.Contains("VerifyOtp") => PubKeyExchangeType.VerificationFlowStream,

            string method when method.Contains("SendMessage") => PubKeyExchangeType.MessageDeliveryStream,
            string method when method.Contains("ReceiveMessage") => PubKeyExchangeType.MessageDeliveryStream,

            string method when method.Contains("UpdatePresence") => PubKeyExchangeType.PresenceStream,
            string method when method.Contains("PresenceStream") => PubKeyExchangeType.PresenceStream,

            _ => PubKeyExchangeType.DataCenterEphemeralConnect
        };
    }

    public async Task<Result<CipherPayload, FailureBase>> EncryptPayload(byte[] payload, uint connectId,
        ServerCallContext context)
    {
        PubKeyExchangeType exchangeType = DetermineExchangeType(context);
        EncryptPayloadActorEvent encryptCommand = new(exchangeType, payload);

        ForwardToConnectActorEvent encryptForwarder = new(connectId, encryptCommand);

        Result<CipherPayload, EcliptixProtocolFailure> encryptResult =
            await _protocolActor.Ask<Result<CipherPayload, EcliptixProtocolFailure>>(
                encryptForwarder, context.CancellationToken);

        if (encryptResult.IsErr)
        {
            return Result<CipherPayload, FailureBase>.Err(encryptResult.UnwrapErr());
        }

        return Result<CipherPayload, FailureBase>.Ok(encryptResult.Unwrap());
    }

    public async Task<Result<byte[], FailureBase>> DecryptPayload(CipherPayload request, uint connectId,
        ServerCallContext context)
    {
        PubKeyExchangeType exchangeType = DetermineExchangeType(context);
        DecryptCipherPayloadActorEvent decryptEvent = new(exchangeType, request);

        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptEvent);

        Result<byte[], EcliptixProtocolFailure> decryptionResult =
            await _protocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(decryptForwarder,
                context.CancellationToken);

        if (decryptionResult.IsErr)
        {
            return Result<byte[], FailureBase>.Err(decryptionResult.UnwrapErr());
        }

        return Result<byte[], FailureBase>.Ok(decryptionResult.Unwrap());
    }

    public async Task<CipherPayload> CreateSuccessResponse<TMessage>(byte[] payload, uint connectId, ServerCallContext context)
        where TMessage : IMessage<TMessage>, new()
    {
        Result<CipherPayload, FailureBase> encryptionResult = await EncryptPayload(payload, connectId, context);

        if (encryptionResult.IsErr)
        {
            return await CreateFailureResponse<TMessage>(encryptionResult.UnwrapErr(), connectId, context);
        }

        return encryptionResult.Unwrap();
    }

    public async Task<CipherPayload> CreateFailureResponse<TMessage>(FailureBase failure, uint connectId,
        ServerCallContext context) where TMessage : IMessage<TMessage>, new()
    {
        context.Status = failure.ToGrpcStatus();
        byte[] emptyPayload = new TMessage().ToByteArray();
        Result<CipherPayload, FailureBase> encryptResult =
            await EncryptPayload(emptyPayload, connectId, context);
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
        if (result.IsErr)
        {
            return await CreateFailureResponse<TSuccess>(result.UnwrapErr(), connectId, context);
        }

        byte[] responsePayload = result.Unwrap().ToByteArray();
        return await CreateSuccessResponse<TSuccess>(responsePayload, connectId, context);
    }
}