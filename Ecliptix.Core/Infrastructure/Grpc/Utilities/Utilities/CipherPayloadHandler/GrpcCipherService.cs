using Akka.Actor;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel.Grpc.Utilities.CipherPayloadHandler;
using Ecliptix.SharedKernel.Actors;
using Grpc.Core;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Serilog;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;

public class GrpcCipherService(IEcliptixActorRegistry actorRegistry) : IGrpcCipherService
{
    private readonly IActorRef _protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);

    private static PubKeyExchangeType GetExchangeTypeFromMetadata(ServerCallContext context)
    {
        Option<string> connectionContextIdOpt = GrpcMetadataHandler.GetConnectionContextId(context.RequestHeaders);

        if (connectionContextIdOpt.IsSome &&
            System.Enum.TryParse(connectionContextIdOpt.Value, true, out PubKeyExchangeType exchangeType) &&
            System.Enum.IsDefined(typeof(PubKeyExchangeType), exchangeType))
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

            Task<Result<SecureEnvelope, EcliptixProtocolFailure>> encryptTask =
                _protocolActor.Ask<Result<SecureEnvelope, EcliptixProtocolFailure>>(
                    encryptForwarder,
                    TimeoutConfiguration.Actor.AskTimeout);
            Result<SecureEnvelope, EcliptixProtocolFailure> result =
                await encryptTask.WaitAsync(context.CancellationToken).ConfigureAwait(false);

            return result.IsErr
                ? Result<SecureEnvelope, FailureBase>.Err(result.UnwrapErr())
                : Result<SecureEnvelope, FailureBase>.Ok(result.Unwrap());
        }
        catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Payload encryption failed for connectId {ConnectId}", connectId);
            return Result<SecureEnvelope, FailureBase>.Err(
                new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, "Payload encryption failed"));
        }
    }

    public async Task<Result<byte[], FailureBase>> DecryptEnvelop(SecureEnvelope secureEnvelope, uint connectId,
        ServerCallContext context)
    {
        try
        {
            PubKeyExchangeType exchangeType = GetExchangeTypeFromMetadata(context);

            DecryptSecureEnvelopeActorEvent decryptCommand = new(exchangeType, secureEnvelope);
            ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptCommand);

            Task<Result<byte[], EcliptixProtocolFailure>> decryptTask =
                _protocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(
                    decryptForwarder,
                    TimeoutConfiguration.Actor.AskTimeout);
            Result<byte[], EcliptixProtocolFailure> decryptionResult =
                await decryptTask.WaitAsync(context.CancellationToken).ConfigureAwait(false);

            if (decryptionResult.IsErr)
            {
                return Result<byte[], FailureBase>.Err(decryptionResult.UnwrapErr());
            }

            using SecureBytes plaintext = SecureBytes.From(decryptionResult.Unwrap());
            byte[] materialized = plaintext.ToArray();
            return Result<byte[], FailureBase>.Ok(materialized);
        }
        catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Result<byte[], FailureBase>.Err(
                new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, "Payload decryption failed"));
        }
    }

    public async Task<SecureEnvelope> CreateFailureResponse(FailureBase failure, uint connectId,
        ServerCallContext context)
    {
        ClientErrorInfo clientError = failure.ToClientError();
        GrpcErrorDescriptor descriptor = failure.ToGrpcDescriptor();

        context.Status = descriptor.CreateStatus(clientError.MessageKey);

        EnvelopeError errorPayload = new()
        {
            ErrorCode = clientError.PublicErrorCode,
            ErrorMessage = clientError.MessageKey,
            OccurredAt = Timestamp.FromDateTime(DateTime.UtcNow)
        };

        if (clientError.Retryable)
        {
            errorPayload.RetryAfterSeconds = 0; // caller can decide backoff policy
        }

        byte[] errorBytes = errorPayload.ToByteArray();

        Result<SecureEnvelope, FailureBase> encryptResult = await EncryptEnvelop([], connectId, context);
        if (encryptResult.IsErr)
        {
            FailureBase encryptFailure = encryptResult.UnwrapErr();
            Log.Error(
                "[GrpcCipherService] Failed to encrypt failure response for ConnectId {ConnectId}: {Error}",
                connectId,
                encryptFailure.Message);
            throw new RpcException(descriptor.CreateStatus(clientError.MessageKey));
        }

        SecureEnvelope envelope = encryptResult.Unwrap();
        envelope.ErrorDetails = ByteString.CopyFrom(errorBytes);
        return envelope;
    }
}
