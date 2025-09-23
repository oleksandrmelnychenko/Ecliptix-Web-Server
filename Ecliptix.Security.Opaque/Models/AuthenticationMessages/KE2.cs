using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Domain.Utilities;
using Ecliptix.Security.Opaque.Failures;

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
        if (data == null)
            return Result<KE2, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput("KE2 data is required"));

        if (data.Length != OpaqueConstants.KE2_LENGTH)
            return Result<KE2, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput($"KE2 must be {OpaqueConstants.KE2_LENGTH} bytes"));

        return Result<KE2, OpaqueServerFailure>.Ok(new KE2(data));
    }
}