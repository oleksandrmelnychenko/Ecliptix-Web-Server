using Ecliptix.OPAQUE.Relay;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.SharedKernel;

namespace Ecliptix.Security.Opaque.Models.AuthenticationMessages;

public sealed class KE3
{
    public byte[] Data { get; }

    private KE3(byte[] data)
    {
        Data = new byte[data.Length];
        Array.Copy(data, Data, data.Length);
    }

    public static Result<KE3, OpaqueRelayFailure> Create(byte[] data)
    {
        return data.Length != OpaqueConstants.KE3_LENGTH
            ? Result<KE3, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.InvalidInput($"KE3 must be {OpaqueConstants.KE3_LENGTH} bytes"))
            : Result<KE3, OpaqueRelayFailure>.Ok(new KE3(data));
    }
}
