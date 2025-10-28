using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Utilities;

namespace Ecliptix.Security.Opaque.Models.AuthenticationMessages;

public sealed class KE2
{
    public byte[] Data { get; }

    private KE2(byte[] data)
    {
        Data = new byte[data.Length];
        Array.Copy(data, Data, data.Length);
    }

    public static Result<KE2, OpaqueServerFailure> Create(byte[] data)
    {
        return data.Length != OpaqueConstants.KE2_LENGTH
            ? Result<KE2, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput($"KE2 must be {OpaqueConstants.KE2_LENGTH} bytes"))
            : Result<KE2, OpaqueServerFailure>.Ok(new KE2(data));
    }
}
