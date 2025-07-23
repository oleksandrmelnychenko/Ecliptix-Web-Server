using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Utilities.CipherPayloadHandler;

public interface IGrpcCipherService
{
    Task<Result<CipherPayload, FailureBase>> EncryptPayload(byte[] payload, uint connectId, ServerCallContext context);
    Task<Result<byte[], FailureBase>> DecryptPayload(CipherPayload cipherPayload, uint connectId, ServerCallContext context);

    Task<CipherPayload> CreateSuccessResponse<T>(byte[] payload, uint connectId, ServerCallContext context)
        where T : IMessage<T>, new();

    Task<CipherPayload> CreateFailureResponse<T>(FailureBase failure, uint connectId, ServerCallContext context)
        where T : IMessage<T>, new();
    
    Task<CipherPayload> CreateFailureResponse(FailureBase failure, uint connectId, ServerCallContext context);
    
    Task<CipherPayload> ProcessResult<TSuccess, TFailure>(Result<TSuccess, TFailure> result, uint connectId, ServerCallContext context)
        where TSuccess : IMessage<TSuccess>, new()
        where TFailure : FailureBase;
}