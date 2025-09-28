using Ecliptix.Protobuf.Common;
using Ecliptix.Utilities;

namespace Ecliptix.Core.Infrastructure.SecureChannel;

public interface ISecureChannelEstablisher
{
    Task<Result<SecureEnvelope, SecureChannelFailure>> EstablishAsync(
        SecureEnvelope request,
        uint connectId,
        CancellationToken cancellationToken = default);
}