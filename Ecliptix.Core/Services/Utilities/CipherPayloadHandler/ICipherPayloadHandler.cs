using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Utilities.CipherPayloadHandler;

public interface ICipherPayloadHandler
{
    Task<Result<CipherPayload, FailureBase>> EncryptResponse(byte[] payload, uint connectId, ServerCallContext context);

    Task<Result<byte[], FailureBase>> DecryptRequest(CipherPayload cipherPayload, uint connectId,
        ServerCallContext context);

    Task<CipherPayload> RespondSuccess<T>(byte[] payload, uint connectId, ServerCallContext context)
        where T : IMessage<T>, new();

    Task<CipherPayload> RespondFailure(FailureBase failure, uint connectId, ServerCallContext context);

    Task<CipherPayload> HandleResult<TSuccess>(Result<TSuccess, FailureBase> result, uint connectId,
        ServerCallContext context)
        where TSuccess : IMessage<TSuccess>, new();
}
