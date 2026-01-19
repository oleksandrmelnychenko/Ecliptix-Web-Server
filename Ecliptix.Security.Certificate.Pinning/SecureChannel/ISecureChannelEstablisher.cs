using Ecliptix.Protobuf.Protocol;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.SharedKernel;

namespace Ecliptix.Security.Certificate.Pinning.SecureChannel;

public interface ISecureChannelEstablisher
{
    Task<Result<SecureEnvelope, SecureChannelFailure>> EstablishAsync(
        SecureEnvelope request,
        uint connectId,
        PubKeyExchangeType exchangeType,
        CancellationToken cancellationToken = default);
}
