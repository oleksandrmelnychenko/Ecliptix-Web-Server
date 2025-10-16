using Ecliptix.Utilities;
using Ecliptix.Protobuf.Common;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;

public interface IGrpcCipherService
{
    Task<Result<SecureEnvelope, FailureBase>> EncryptEnvelop(byte[] envelop, uint connectId, ServerCallContext context);
    Task<Result<byte[], FailureBase>> DecryptEnvelop(SecureEnvelope secureEnvelope, uint connectId, ServerCallContext context);
    Task<SecureEnvelope> CreateFailureResponse(FailureBase failure, uint connectId, ServerCallContext context);
}