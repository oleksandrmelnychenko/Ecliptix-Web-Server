using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.SecureEnvelopeHandler;

public interface IGrpcCipherService
{
    Task<Result<SecureEnvelope, FailureBase>> EncryptPayload(byte[] payload, uint connectId, ServerCallContext context);
    Task<Result<byte[], FailureBase>> DecryptPayload(SecureEnvelope secureEnvelope, uint connectId, ServerCallContext context);

    Task<SecureEnvelope> CreateFailureResponse(FailureBase failure, uint connectId, ServerCallContext context);
}