using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;

public interface IGrpcCipherService
{
    Task<Result<CipherPayload, FailureBase>> EncryptPayload(byte[] payload, uint connectId, ServerCallContext context);
    Task<Result<byte[], FailureBase>> DecryptPayload(CipherPayload cipherPayload, uint connectId, ServerCallContext context);

    Task<CipherPayload> CreateFailureResponse(FailureBase failure, uint connectId, ServerCallContext context);
}