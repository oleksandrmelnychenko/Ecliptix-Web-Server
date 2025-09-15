using Akka.Actor;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Grpc.Core;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;

public class GrpcCipherService(IEcliptixActorRegistry actorRegistry) : IGrpcCipherService
{
    private readonly IActorRef _protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);

    private static PubKeyExchangeType GetExchangeTypeFromMetadata(ServerCallContext context)
    {
        string connectionContextId = GrpcMetadataHandler.GetConnectionContextId(context.RequestHeaders);

        if (Enum.TryParse(connectionContextId, true, out PubKeyExchangeType exchangeType) &&
            Enum.IsDefined(exchangeType))
        {
            return exchangeType;
        }

        return PubKeyExchangeType.DataCenterEphemeralConnect;
    }

    public async Task<Result<CipherPayload, FailureBase>> EncryptPayload(byte[] payload, uint connectId,
        ServerCallContext context)
    {
        PubKeyExchangeType exchangeType = GetExchangeTypeFromMetadata(context);
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
        PubKeyExchangeType exchangeType = GetExchangeTypeFromMetadata(context);
        DecryptCipherPayloadActorEvent decryptEvent = new(exchangeType, request);

        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptEvent);

        Result<byte[], EcliptixProtocolFailure> decryptionResult =
            await _protocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(decryptForwarder,
                context.CancellationToken);

        return decryptionResult.IsErr
            ? Result<byte[], FailureBase>.Err(decryptionResult.UnwrapErr())
            : Result<byte[], FailureBase>.Ok(decryptionResult.Unwrap());
    }

    public async Task<CipherPayload> CreateFailureResponse(FailureBase failure, uint connectId,
        ServerCallContext context)
    {
        context.Status = failure.ToGrpcStatus();
        Result<CipherPayload, FailureBase> encryptResult = await EncryptPayload([], connectId, context);
        return encryptResult.IsErr ? new CipherPayload() : encryptResult.Unwrap();
    }
}