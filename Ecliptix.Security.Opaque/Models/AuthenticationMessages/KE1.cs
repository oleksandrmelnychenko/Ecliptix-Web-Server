using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Domain.Utilities;
using Ecliptix.Security.Opaque.Failures;

namespace Ecliptix.Security.Opaque.Models.AuthenticationMessages;

public sealed class KE1
{
    public byte[] Data { get; }

    private KE1(byte[] data)
    {
        Data = new byte[data.Length];
        Array.Copy(data, Data, data.Length);
    }

    public static Result<KE1, OpaqueServerFailure> Create(byte[] data)
    {
        if (data == null)
            return Result<KE1, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(OpaqueServerConstants.ValidationMessages.KE1DataRequired));

        if (data.Length != OpaqueConstants.KE1_LENGTH)
            return Result<KE1, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput($"KE1 must be {OpaqueConstants.KE1_LENGTH} bytes"));

        return Result<KE1, OpaqueServerFailure>.Ok(new KE1(data));
    }
}