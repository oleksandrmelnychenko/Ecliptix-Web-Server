using Ecliptix.Protobuf.Common;
using Ecliptix.SharedKernel;

namespace Ecliptix.DeviceProvisioning.Infrastructure.SecureChannel;

public interface ISecureChannelEstablisher
{
    Task<Result<SecureEnvelope, SecureChannelFailure>> EstablishAsync(
        SecureEnvelope request,
        uint connectId,
        CancellationToken cancellationToken = default);
}
