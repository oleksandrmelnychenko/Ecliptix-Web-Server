using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Domain.Utilities;
using Ecliptix.Security.Opaque.Failures;

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
        if (data == null)
            return Result<RegistrationResponse, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput("Registration response data is required"));

        if (data.Length != OpaqueConstants.REGISTRATION_RESPONSE_LENGTH)
            return Result<RegistrationResponse, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput($"Registration response must be {OpaqueConstants.REGISTRATION_RESPONSE_LENGTH} bytes"));

        return Result<RegistrationResponse, OpaqueServerFailure>.Ok(new RegistrationResponse(data));
    }
}