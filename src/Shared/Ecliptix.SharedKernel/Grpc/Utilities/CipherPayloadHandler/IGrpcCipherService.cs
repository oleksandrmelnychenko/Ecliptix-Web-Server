using Ecliptix.Protobuf.Common;
using Ecliptix.SharedKernel;
using Grpc.Core;

namespace Ecliptix.SharedKernel.Grpc.Utilities.CipherPayloadHandler;

public interface IGrpcCipherService
{
    Task<Result<SecureEnvelope, FailureBase>> EncryptEnvelop(byte[] envelop, uint connectId, ServerCallContext context);
    Task<Result<byte[], FailureBase>> DecryptEnvelop(SecureEnvelope secureEnvelope, uint connectId, ServerCallContext context);
    Task<SecureEnvelope> CreateFailureResponse(FailureBase failure, uint connectId, ServerCallContext context);
}
