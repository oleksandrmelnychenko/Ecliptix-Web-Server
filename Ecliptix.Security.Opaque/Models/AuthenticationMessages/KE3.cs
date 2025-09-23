using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Domain.Utilities;
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
        if (data == null)
            return Result<KE3, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(OpaqueServerConstants.ValidationMessages.KE3DataRequired));

        if (data.Length != OpaqueConstants.KE3_LENGTH)
            return Result<KE3, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput($"KE3 must be {OpaqueConstants.KE3_LENGTH} bytes"));

        return Result<KE3, OpaqueServerFailure>.Ok(new KE3(data));
    }
}