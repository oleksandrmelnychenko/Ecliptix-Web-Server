using System.Buffers;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures.Sodium;

namespace Ecliptix.Core.Domain.Protocol;

public sealed class RatchetChainKey : IDisposable, IEquatable<RatchetChainKey>
{
    private SodiumSecureMemoryHandle _keyHandle;
    private bool _disposed;

    private RatchetChainKey(uint index, SodiumSecureMemoryHandle keyHandle)
    {
        Index = index;
        _keyHandle = keyHandle;
        _disposed = false;
    }

    ~RatchetChainKey()
    {
        Dispose(false);
    }

    public uint Index { get; }

    public void Dispose()
    {
        Dispose(true);
    }

    public bool Equals(RatchetChainKey? other)
    {
        if (other is null) return false;
        return
            Index == other.Index &&
            _disposed ==
            other._disposed;
    }

    public Result<Unit, EcliptixProtocolFailure> ReadKeyMaterial(Span<byte> destination)
    {
        if (_disposed)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(RatchetChainKey)));

        if (destination.Length < Constants.AesKeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.BufferTooSmall(
                    $"Destination buffer must be at least {Constants.AesKeySize} bytes, but was {destination.Length}."));

        return _keyHandle.Read(destination[..Constants.AesKeySize]).MapSodiumFailure();
    }

    public static Result<RatchetChainKey, EcliptixProtocolFailure> New(uint index, ReadOnlySpan<byte> keyMaterial)
    {
        if (keyMaterial.Length != Constants.AesKeySize)
            return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput(
                    $"Key material must be exactly {Constants.AesKeySize} bytes long, but was {keyMaterial.Length}."));

        Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> allocateResult =
            SodiumSecureMemoryHandle.Allocate(Constants.AesKeySize).MapSodiumFailure();
        if (allocateResult.IsErr)
            return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(allocateResult.UnwrapErr());

        SodiumSecureMemoryHandle keyHandle = allocateResult.Unwrap();

        Result<Unit, EcliptixProtocolFailure> writeResult = keyHandle.Write(keyMaterial).MapSodiumFailure();
        if (writeResult.IsErr)
        {
            keyHandle.Dispose();
            return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(writeResult.UnwrapErr());
        }

        RatchetChainKey messageKey = new(index, keyHandle);

        return Result<RatchetChainKey, EcliptixProtocolFailure>.Ok(messageKey);
    }

    public static Result<RatchetChainKey, EcliptixProtocolFailure> DeriveFromChainKey(byte[] chainKey, uint messageIndex)
    {
        if (chainKey.Length != Constants.X25519KeySize)
            return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput($"Chain key must be {Constants.X25519KeySize} bytes"));

        try
        {
            byte[] messageKeyBytes = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
            try
            {
                System.Security.Cryptography.HKDF.DeriveKey(
                    System.Security.Cryptography.HashAlgorithmName.SHA256,
                    ikm: chainKey,
                    output: messageKeyBytes.AsSpan(0, Constants.AesKeySize),
                    salt: null,
                    info: EcliptixProtocolChainStep.MsgInfo
                );

                return New(messageIndex, messageKeyBytes.AsSpan(0, Constants.AesKeySize));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(messageKeyBytes, clearArray: true);
            }
        }
        catch (Exception ex)
        {
            return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.DeriveKey("Failed to derive message key from chain key using HKDF", ex));
        }
    }

    public override bool Equals(object? obj)
    {
        return obj is RatchetChainKey other && Equals(other);
    }

    public override int GetHashCode()
    {
        return Index.GetHashCode();
    }

    public static bool operator ==(RatchetChainKey? left, RatchetChainKey? right)
    {
        if (ReferenceEquals(left, right)) return true;
        if (left is null || right is null) return false;
        return left.Equals(right);
    }

    public static bool operator !=(RatchetChainKey? left, RatchetChainKey? right)
    {
        return !(left == right);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed) return;
        if (disposing)
        {
            _keyHandle.Dispose();
            _keyHandle = null!;
        }

        _disposed = true;
    }
}
