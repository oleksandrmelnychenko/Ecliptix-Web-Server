using Ecliptix.Core.Protocol.Failures;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldMessageKey : IDisposable, IEquatable<ShieldMessageKey>
{
    public uint Index { get; }

    private SodiumSecureMemoryHandle _keyHandle;
    private bool _disposed;

    private ShieldMessageKey(uint index, SodiumSecureMemoryHandle keyHandle)
    {
        Index = index;
        _keyHandle = keyHandle;
        _disposed = false;
    }

    public static Result<ShieldMessageKey, EcliptixProtocolFailure> New(uint index, ReadOnlySpan<byte> keyMaterial)
    {
        if (keyMaterial.Length != Constants.X25519KeySize)
        {
            return Result<ShieldMessageKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput(
                    $"Key material must be exactly {Constants.X25519KeySize} bytes long, but was {keyMaterial.Length}."));
        }

        Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> allocateResult =
            SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize).MapSodiumFailure();
        if (allocateResult.IsErr)
        {
            return Result<ShieldMessageKey, EcliptixProtocolFailure>.Err(allocateResult.UnwrapErr());
        }

        SodiumSecureMemoryHandle keyHandle = allocateResult.Unwrap();

        Result<Unit, EcliptixProtocolFailure> writeResult = keyHandle.Write(keyMaterial).MapSodiumFailure();
        if (writeResult.IsErr)
        {
            keyHandle.Dispose();
            return Result<ShieldMessageKey, EcliptixProtocolFailure>.Err(writeResult.UnwrapErr());
        }

        ShieldMessageKey messageKey = new(index, keyHandle);
        return Result<ShieldMessageKey, EcliptixProtocolFailure>.Ok(messageKey);
    }

    public Result<Unit, EcliptixProtocolFailure> ReadKeyMaterial(Span<byte> destination)
    {
        if (_disposed)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ShieldMessageKey)));
        }

        if (destination.Length < Constants.X25519KeySize)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.BufferTooSmall(
                    $"Destination buffer must be at least {Constants.X25519KeySize} bytes, but was {destination.Length}."));
        }

        return _keyHandle.Read(destination[..Constants.X25519KeySize]).MapSodiumFailure();
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _keyHandle?.Dispose();
                _keyHandle = null!;
            }

            _disposed = true;
        }
    }

    ~ShieldMessageKey()
    {
        Dispose(false);
    }

    public bool Equals(ShieldMessageKey? other)
    {
        if (other is null) return false;
        return
            Index == other.Index &&
            _disposed ==
            other._disposed;
    }

    public override bool Equals(object? obj) =>
        obj is ShieldMessageKey other && Equals(other);

    public override int GetHashCode() =>
        Index.GetHashCode();

    public static bool operator ==(ShieldMessageKey? left, ShieldMessageKey? right)
    {
        if (ReferenceEquals(left, right)) return true;
        if (left is null || right is null) return false;
        return left.Equals(right);
    }

    public static bool operator !=(ShieldMessageKey? left, ShieldMessageKey? right)
    {
        return !(left == right);
    }
}