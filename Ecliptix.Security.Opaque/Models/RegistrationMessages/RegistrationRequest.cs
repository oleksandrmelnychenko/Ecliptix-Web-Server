using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Utilities;
using Ecliptix.Security.Opaque.Failures;

namespace Ecliptix.Security.Opaque.Models.RegistrationMessages;

public sealed class RegistrationRequest
{
    public byte[] Data { get; }

    private RegistrationRequest(byte[] data)
    {
        Data = new byte[data.Length];
        Array.Copy(data, Data, data.Length);
    }

    public static Result<RegistrationRequest, OpaqueServerFailure> Create(byte[] data)
    {
        if (data == null)
            return Result<RegistrationRequest, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(OpaqueServerConstants.ValidationMessages.RegistrationRequestDataRequired));

        if (data.Length != OpaqueConstants.REGISTRATION_REQUEST_LENGTH)
            return Result<RegistrationRequest, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput($"Registration request must be {OpaqueConstants.REGISTRATION_REQUEST_LENGTH} bytes"));

        return Result<RegistrationRequest, OpaqueServerFailure>.Ok(new RegistrationRequest(data));
    }
}