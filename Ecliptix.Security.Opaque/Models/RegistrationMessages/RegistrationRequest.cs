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

    public static Result<RegistrationRequest, OpaqueServerFailure> Create(byte[] data) =>
        data.Length != OpaqueConstants.REGISTRATION_REQUEST_LENGTH
            ? Result<RegistrationRequest, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput(
                    $"Registration request must be {OpaqueConstants.REGISTRATION_REQUEST_LENGTH} bytes"))
            : Result<RegistrationRequest, OpaqueServerFailure>.Ok(new RegistrationRequest(data));
}