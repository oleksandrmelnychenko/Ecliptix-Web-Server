using Akka.Actor;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Grpc.Core;
using Serilog;

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

    public async Task<Result<SecureEnvelope, FailureBase>> EncryptEnvelop(byte[] envelop, uint connectId,
        ServerCallContext context)
    {
        try
        {
            PubKeyExchangeType exchangeType = GetExchangeTypeFromMetadata(context);

            EncryptPayloadActorEvent encryptCommand = new(exchangeType, envelop);
            ForwardToConnectActorEvent encryptForwarder = new(connectId, encryptCommand);

            Result<SecureEnvelope, EcliptixProtocolFailure> result =
                await _protocolActor.Ask<Result<SecureEnvelope, EcliptixProtocolFailure>>(
                    encryptForwarder, context.CancellationToken);

            return result.IsErr
                ? Result<SecureEnvelope, FailureBase>.Err(result.UnwrapErr())
                : Result<SecureEnvelope, FailureBase>.Ok(result.Unwrap());
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Payload encryption failed for connectId {ConnectId}", connectId);
            return Result<SecureEnvelope, FailureBase>.Err(
                new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, "Payload encryption failed"));
        }
    }

    public async Task<Result<byte[], FailureBase>> DecryptEnvelop(SecureEnvelope request, uint connectId,
        ServerCallContext context)
    {
        try
        {
            PubKeyExchangeType exchangeType = GetExchangeTypeFromMetadata(context);

            DecryptSecureEnvelopeActorEvent decryptCommand = new(exchangeType, request);
            ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptCommand);

            Result<byte[], EcliptixProtocolFailure> decryptionResult =
                await _protocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(
                    decryptForwarder, context.CancellationToken);

            return decryptionResult.IsErr
                ? Result<byte[], FailureBase>.Err(decryptionResult.UnwrapErr())
                : Result<byte[], FailureBase>.Ok(decryptionResult.Unwrap());
        }
        catch (Exception ex)
        {
            return Result<byte[], FailureBase>.Err(
                new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, "Payload decryption failed"));
        }
    }

    public async Task<SecureEnvelope> CreateFailureResponse(FailureBase failure, uint connectId,
        ServerCallContext context)
    {
        context.Status = failure.ToGrpcStatus();
        Result<SecureEnvelope, FailureBase> encryptResult = await EncryptEnvelop([], connectId, context);
        return encryptResult.IsErr ? new SecureEnvelope() : encryptResult.Unwrap();
    }
}