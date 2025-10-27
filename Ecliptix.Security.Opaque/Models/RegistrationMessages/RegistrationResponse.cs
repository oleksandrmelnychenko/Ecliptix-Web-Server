using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Utilities;

namespace Ecliptix.Security.Opaque.Models.RegistrationMessages;

public sealed class RegistrationResponse
{
    public byte[] Data { get; }

    private RegistrationResponse(byte[] data)
    {
        Data = new byte[data.Length];
        Array.Copy(data, Data, data.Length);
    }

    public static Result<RegistrationResponse, OpaqueServerFailure> Create(byte[] data)
    {
        return data.Length != OpaqueConstants.REGISTRATION_RESPONSE_LENGTH
            ? Result<RegistrationResponse, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput(
                    $"Registration response must be {OpaqueConstants.REGISTRATION_RESPONSE_LENGTH} bytes"))
            : Result<RegistrationResponse, OpaqueServerFailure>.Ok(new RegistrationResponse(data));
    }
}
