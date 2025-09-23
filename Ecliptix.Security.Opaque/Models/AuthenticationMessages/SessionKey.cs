using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Domain.Utilities;
using Ecliptix.Security.Opaque.Failures;

namespace Ecliptix.Security.Opaque.Models.AuthenticationMessages;

public sealed class SessionKey
{
    public byte[] Data { get; }

    private SessionKey(byte[] data)
    {
        Data = new byte[data.Length];
        Array.Copy(data, Data, data.Length);
    }

    public static Result<SessionKey, OpaqueServerFailure> Create(byte[] data)
    {
        if (data == null)
            return Result<SessionKey, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput("Session key data is required"));

        if (data.Length != OpaqueConstants.HASH_LENGTH)
            return Result<SessionKey, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput($"Session key must be {OpaqueConstants.HASH_LENGTH} bytes"));

        return Result<SessionKey, OpaqueServerFailure>.Ok(new SessionKey(data));
    }

    ~SessionKey()
    {
        Array.Clear(Data, 0, Data.Length);
    }
}