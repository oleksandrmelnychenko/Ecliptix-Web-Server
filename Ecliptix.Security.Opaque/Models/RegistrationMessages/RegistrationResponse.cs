using Ecliptix.OPAQUE.Relay;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.SharedKernel;

namespace Ecliptix.Security.Opaque.Models.RegistrationMessages;

public sealed class RegistrationResponse
{
    public byte[] Data { get; }

    private RegistrationResponse(byte[] data)
    {
        Data = new byte[data.Length];
        Array.Copy(data, Data, data.Length);
    }

    public static Result<RegistrationResponse, OpaqueRelayFailure> Create(byte[] data)
    {
        return data.Length != OpaqueConstants.REGISTRATION_RESPONSE_LENGTH
            ? Result<RegistrationResponse, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.InvalidInput(
                    $"Registration response must be {OpaqueConstants.REGISTRATION_RESPONSE_LENGTH} bytes"))
            : Result<RegistrationResponse, OpaqueRelayFailure>.Ok(new RegistrationResponse(data));
    }
}
