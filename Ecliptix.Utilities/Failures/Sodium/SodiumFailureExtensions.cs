using Ecliptix.Utilities;

namespace Ecliptix.Utilities.Failures.Sodium;

public static class SodiumFailureExtensions
{
    public static EcliptixProtocolFailure ToEcliptixProtocolFailure(this SodiumFailure sodiumFailure)
    {
        return sodiumFailure.Type switch
        {
            SodiumFailureType.InitializationFailed => EcliptixProtocolFailure.Generic(sodiumFailure.Message,
                sodiumFailure.InnerException),
            SodiumFailureType.LibraryNotFound => EcliptixProtocolFailure.Generic(sodiumFailure.Message,
                sodiumFailure.InnerException),
            SodiumFailureType.AllocationFailed => EcliptixProtocolFailure.AllocationFailed(sodiumFailure.Message,
                sodiumFailure.InnerException),
            SodiumFailureType.MemoryPinningFailed => EcliptixProtocolFailure.PinningFailure(sodiumFailure.Message,
                sodiumFailure.InnerException),
            SodiumFailureType.SecureWipeFailed => EcliptixProtocolFailure.MemoryBufferError(sodiumFailure.Message,
                sodiumFailure.InnerException),
            SodiumFailureType.MemoryProtectionFailed => EcliptixProtocolFailure.MemoryBufferError(sodiumFailure.Message,
                sodiumFailure.InnerException),
            SodiumFailureType.NullPointer => EcliptixProtocolFailure.ObjectDisposed(sodiumFailure.Message),
            SodiumFailureType.InvalidBufferSize => EcliptixProtocolFailure.InvalidInput(sodiumFailure.Message),
            SodiumFailureType.BufferTooSmall => EcliptixProtocolFailure.BufferTooSmall(sodiumFailure.Message),
            SodiumFailureType.BufferTooLarge => EcliptixProtocolFailure.DataTooLarge(sodiumFailure.Message),
            _ => EcliptixProtocolFailure.Generic(sodiumFailure.Message, sodiumFailure.InnerException)
        };
    }
}

public static class ResultSodiumExtensions
{
    public static Result<T, EcliptixProtocolFailure> MapSodiumFailure<T>(this Result<T, SodiumFailure> result)
    {
        return result.IsOk
            ? Result<T, EcliptixProtocolFailure>.Ok(result.Unwrap())
            : Result<T, EcliptixProtocolFailure>.Err(result.UnwrapErr().ToEcliptixProtocolFailure());
    }
}
