using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Utilities;
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
        return data.Length != OpaqueConstants.HASH_LENGTH
            ? Result<SessionKey, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput($"Session key must be {OpaqueConstants.HASH_LENGTH} bytes"))
            : Result<SessionKey, OpaqueServerFailure>.Ok(new SessionKey(data));
    }

    ~SessionKey()
    {
        Array.Clear(Data, 0, Data.Length);
    }
}