using Ecliptix.SecureProtocol.Domain.ProtocolNative;
using Ecliptix.SharedKernel;

namespace Ecliptix.SecureProtocol.Domain.Protocol;

public sealed class ProtocolKeyService : IProtocolKeyService, IDisposable
{
    private readonly object _lock = new();
    private EcliptixIdentityKeys? _identityKeys;
    private byte[]? _cachedKyberKey;
    private byte[]? _cachedEd25519Key;
    private byte[]? _cachedX25519Key;
    private bool _disposed;

    public Result<Unit, EcliptixProtocolFailure> Initialize(byte[] seed)
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolKeyService)));
            }

            if (_identityKeys != null)
            {
                return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
            }

            Result<EcliptixIdentityKeys, EcliptixProtocolFailure> createResult =
                EcliptixIdentityKeys.CreateFromSeed(seed);

            if (createResult.IsErr)
            {
                return Result<Unit, EcliptixProtocolFailure>.Err(createResult.UnwrapErr());
            }

            _identityKeys = createResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> kyberResult = _identityKeys.GetPublicKyber();
            if (kyberResult.IsErr)
            {
                _identityKeys.Dispose();
                _identityKeys = null;
                return Result<Unit, EcliptixProtocolFailure>.Err(kyberResult.UnwrapErr());
            }
            _cachedKyberKey = kyberResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> ed25519Result = _identityKeys.GetPublicEd25519();
            if (ed25519Result.IsErr)
            {
                _identityKeys.Dispose();
                _identityKeys = null;
                return Result<Unit, EcliptixProtocolFailure>.Err(ed25519Result.UnwrapErr());
            }
            _cachedEd25519Key = ed25519Result.Unwrap();

            Result<byte[], EcliptixProtocolFailure> x25519Result = _identityKeys.GetPublicX25519();
            if (x25519Result.IsErr)
            {
                _identityKeys.Dispose();
                _identityKeys = null;
                return Result<Unit, EcliptixProtocolFailure>.Err(x25519Result.UnwrapErr());
            }
            _cachedX25519Key = x25519Result.Unwrap();

            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }
    }

    public Result<byte[], EcliptixProtocolFailure> GetServerKyberPublicKey()
    {
        if (_disposed)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolKeyService)));
        }

        if (_cachedKyberKey == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Protocol key service not initialized"));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(_cachedKyberKey);
    }

    public Result<byte[], EcliptixProtocolFailure> GetServerEd25519PublicKey()
    {
        if (_disposed)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolKeyService)));
        }

        if (_cachedEd25519Key == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Protocol key service not initialized"));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(_cachedEd25519Key);
    }

    public Result<byte[], EcliptixProtocolFailure> GetServerX25519PublicKey()
    {
        if (_disposed)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolKeyService)));
        }

        if (_cachedX25519Key == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Protocol key service not initialized"));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(_cachedX25519Key);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _identityKeys?.Dispose();
            _identityKeys = null;
            _cachedKyberKey = null;
            _cachedEd25519Key = null;
            _cachedX25519Key = null;
            _disposed = true;
        }
    }
}
