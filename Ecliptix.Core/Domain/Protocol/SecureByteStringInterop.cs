using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures.Sodium;
using Google.Protobuf;

namespace Ecliptix.Core.Domain.Protocol;

public static class SecureByteStringInterop
{
    public static void SecureCopyWithCleanup(ByteString source, out byte[] destination)
    {
        if (source.IsEmpty)
        {
            destination = [];
            return;
        }

        destination = new byte[source.Length];
        source.Span.CopyTo(destination);
    }

    public static Result<ByteString, SodiumFailure> CreateByteStringFromSecureMemorySpan(SodiumSecureMemoryHandle source, int length)
    {
        ArgumentNullException.ThrowIfNull(source);

        switch (length)
        {
            case < 0:
                return Result<ByteString, SodiumFailure>.Err(
                    SodiumFailure.InvalidBufferSize($"Negative length requested: {length}"));
            case 0:
                return Result<ByteString, SodiumFailure>.Ok(ByteString.Empty);
        }

        if (length > source.Length)
            return Result<ByteString, SodiumFailure>.Err(
                SodiumFailure.InvalidBufferSize($"Requested length {length} exceeds handle length {source.Length}"));

        Span<byte> tempBuffer = stackalloc byte[length];
        Result<Unit, SodiumFailure> readResult = source.Read(tempBuffer);
        if (readResult.IsErr)
            return Result<ByteString, SodiumFailure>.Err(readResult.UnwrapErr());

        return Result<ByteString, SodiumFailure>.Ok(ByteString.CopyFrom(tempBuffer));
    }
}