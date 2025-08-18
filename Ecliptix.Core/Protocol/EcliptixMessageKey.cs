using Ecliptix.Core.Protocol.Failures;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Protocol;

public sealed class EcliptixMessageKey : IDisposable, IEquatable<EcliptixMessageKey>
{
    private bool _disposed;
    private SodiumSecureMemoryHandle _keyHandle;

    private EcliptixMessageKey(uint index, SodiumSecureMemoryHandle keyHandle)
    {
        Index = index;
        _keyHandle = keyHandle;
        _disposed = false;
    }

    public uint Index { get; }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public bool Equals(EcliptixMessageKey? other)
    {
        if (other is null) return false;
        return Index == other.Index;
    }

    public static Result<EcliptixMessageKey, EcliptixProtocolFailure> New(uint index, ReadOnlySpan<byte> keyMaterial)
    {
        if (keyMaterial.Length != Constants.X25519KeySize)
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput(
                    $"Key material must be exactly {Constants.X25519KeySize} bytes long, but was {keyMaterial.Length}."));

        Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> allocateResult =
            SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize).MapSodiumFailure();
        if (allocateResult.IsErr)
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(allocateResult.UnwrapErr());

        SodiumSecureMemoryHandle keyHandle = allocateResult.Unwrap();

        Result<Unit, EcliptixProtocolFailure> writeResult = keyHandle.Write(keyMaterial).MapSodiumFailure();
        if (writeResult.IsErr)
        {
            keyHandle.Dispose();
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(writeResult.UnwrapErr());
        }

        EcliptixMessageKey messageKey = new(index, keyHandle);

        return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Ok(messageKey);
    }

    public Result<Unit, EcliptixProtocolFailure> ReadKeyMaterial(Span<byte> destination)
    {
        if (_disposed)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixMessageKey)));

        if (destination.Length < Constants.X25519KeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.BufferTooSmall(
                    $"Destination buffer must be at least {Constants.X25519KeySize} bytes, but was {destination.Length}."));

        return _keyHandle.Read(destination[..Constants.X25519KeySize]).MapSodiumFailure();
    }

    public static Result<EcliptixMessageKey, EcliptixProtocolFailure> DeriveFromChainKey(byte[] chainKey, uint messageIndex)
    {
        if (chainKey.Length != Constants.X25519KeySize)
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput($"Chain key must be {Constants.X25519KeySize} bytes"));

        try
        {
            byte[] messageKeyBytes = new byte[Constants.AesKeySize];
            try
            {
                // Use HKDF to match client implementation
                System.Security.Cryptography.HKDF.DeriveKey(
                    System.Security.Cryptography.HashAlgorithmName.SHA256,
                    ikm: chainKey,
                    output: messageKeyBytes,
                    salt: null,
                    info: Constants.MsgInfo
                );

                return New(messageIndex, messageKeyBytes);
            }
            finally
            {
                SodiumInterop.SecureWipe(messageKeyBytes);
            }
        }
        catch (Exception ex)
        {
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.DeriveKey("Failed to derive message key from chain key using HKDF", ex));
        }
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

    ~EcliptixMessageKey()
    {
        Dispose(false);
    }

    public override bool Equals(object? obj)
    {
        return obj is EcliptixMessageKey other && Equals(other);
    }

    public override int GetHashCode()
    {
        return Index.GetHashCode();
    }

    public static bool operator ==(EcliptixMessageKey? left, EcliptixMessageKey? right)
    {
        if (ReferenceEquals(left, right)) return true;
        if (left is null || right is null) return false;
        return left.Equals(right);
    }

    public static bool operator !=(EcliptixMessageKey? left, EcliptixMessageKey? right)
    {
        return !(left == right);
    }
}
