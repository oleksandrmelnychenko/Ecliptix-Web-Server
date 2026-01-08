using Ecliptix.SecureProtocol.Domain.ProtocolNative;
using Ecliptix.SharedKernel;

namespace Ecliptix.SecureProtocol.Domain.Protocol;

public interface IProtocolKeyService
{
    Result<Unit, EcliptixProtocolFailure> Initialize(byte[] seed);
    Result<byte[], EcliptixProtocolFailure> GetServerKyberPublicKey();
    Result<byte[], EcliptixProtocolFailure> GetServerEd25519PublicKey();
    Result<byte[], EcliptixProtocolFailure> GetServerX25519PublicKey();
}
