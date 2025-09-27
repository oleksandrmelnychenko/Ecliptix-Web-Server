using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Utilities;
using Ecliptix.Security.Opaque.Failures;

namespace Ecliptix.Security.Opaque.Models.AuthenticationMessages;

public sealed class KE3
{
    public byte[] Data { get; }

    private KE3(byte[] data)
    {
        Data = new byte[data.Length];
        Array.Copy(data, Data, data.Length);
    }

    public static Result<KE3, OpaqueServerFailure> Create(byte[] data)
    {
        return data.Length != OpaqueConstants.KE3_LENGTH
            ? Result<KE3, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput($"KE3 must be {OpaqueConstants.KE3_LENGTH} bytes"))
            : Result<KE3, OpaqueServerFailure>.Ok(new KE3(data));
    }
}