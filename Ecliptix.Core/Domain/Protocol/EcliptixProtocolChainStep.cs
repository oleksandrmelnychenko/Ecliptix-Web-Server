using System.Buffers;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Utilities.Failures.Sodium;
using Google.Protobuf;
using Serilog;
using Serilog.Events;

namespace Ecliptix.Core.Domain.Protocol;

public sealed class EcliptixProtocolChainStep : IDisposable
{
    private const uint DefaultCacheWindowSize = Constants.DefaultCacheWindowSize;
    internal static readonly byte[] MsgInfo = { 0x01 };
    internal static readonly byte[] ChainInfo = { 0x02 };

    private static readonly Result<Unit, EcliptixProtocolFailure> OkResult =
        Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);

    private readonly uint _cacheWindow;
    private readonly RatchetChainStepType _stepType;
    private readonly SodiumSecureMemoryHandle _chainKeyHandle;
    private uint _currentIndex;
    private SodiumSecureMemoryHandle? _dhPrivateKeyHandle;
    private byte[]? _dhPublicKey;
    private bool _disposed;

    private readonly SortedDictionary<uint, RatchetChainKey> _messageKeys;

    private EcliptixProtocolChainStep(
        RatchetChainStepType stepType,
        SodiumSecureMemoryHandle chainKeyHandle,
        SodiumSecureMemoryHandle? dhPrivateKeyHandle,
        byte[]? dhPublicKey,
        uint cacheWindowSize)
    {
        _stepType = stepType;
        _chainKeyHandle = chainKeyHandle ?? throw new ArgumentNullException(nameof(chainKeyHandle));
        _dhPrivateKeyHandle = dhPrivateKeyHandle;
        _dhPublicKey = dhPublicKey;
        _cacheWindow = cacheWindowSize > 0 ? cacheWindowSize : DefaultCacheWindowSize;
        _messageKeys = new SortedDictionary<uint, RatchetChainKey>();
        _currentIndex = 0;
        _disposed = false;
    }

    public Result<uint, EcliptixProtocolFailure> GetCurrentIndex()
    {
        return _disposed
            ? Result<uint, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolChainStep)))
            : Result<uint, EcliptixProtocolFailure>.Ok(_currentIndex);
    }

    internal SodiumSecureMemoryHandle? GetDhPrivateKeyHandle() => _dhPrivateKeyHandle;

    public static Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> FromProtoState(RatchetChainStepType stepType,
        ChainStepState proto)
    {
        SecureByteStringInterop.SecureCopyWithCleanup(proto.ChainKey, out byte[] chainKeyBytes);
        byte[]? dhPrivKeyBytes = null;
        if (!proto.DhPrivateKey.IsEmpty)
        {
            SecureByteStringInterop.SecureCopyWithCleanup(proto.DhPrivateKey, out dhPrivKeyBytes);
        }
        byte[]? dhPubKeyBytes = null;
        if (!proto.DhPublicKey.IsEmpty)
        {
            SecureByteStringInterop.SecureCopyWithCleanup(proto.DhPublicKey, out dhPubKeyBytes);
        }

        Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> createResult =
            Create(stepType, chainKeyBytes, dhPrivKeyBytes, dhPubKeyBytes);
        if (createResult.IsErr)
        {
            return createResult;
        }

        EcliptixProtocolChainStep chainStep = createResult.Unwrap();
        chainStep.SetCurrentIndex(proto.CurrentIndex)
            .Unwrap();

        foreach (CachedMessageKey cachedKey in proto.CachedMessageKeys)
        {
            Result<RatchetChainKey, EcliptixProtocolFailure> messageKeyResult =
                RatchetChainKey.New(cachedKey.Index, cachedKey.KeyMaterial.Span);

            if (messageKeyResult.IsOk)
            {
                RatchetChainKey messageKey = messageKeyResult.Unwrap();
                if (!chainStep._messageKeys.TryAdd(cachedKey.Index, messageKey))
                {
                    messageKey.Dispose();
                }
            }
        }

        return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Ok(chainStep);
    }

    internal Result<Unit, EcliptixProtocolFailure> SetCurrentIndex(uint value)
    {
        if (_disposed)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolChainStep)));
        _currentIndex = value;
        return OkResult;
    }

    internal Result<RatchetChainKey, EcliptixProtocolFailure> GetOrDeriveKeyFor(uint targetIndex)
    {
        if (_disposed)
            return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolChainStep)));

        if (_messageKeys.TryGetValue(targetIndex, out RatchetChainKey? cachedKey))
        {
            return Result<RatchetChainKey, EcliptixProtocolFailure>.Ok(cachedKey);
        }

        Result<uint, EcliptixProtocolFailure> currentIndexResult = GetCurrentIndex();
        if (currentIndexResult.IsErr)
            return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(currentIndexResult.UnwrapErr());

        uint currentIndex = currentIndexResult.Unwrap();

        if (targetIndex <= currentIndex)
            return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput(
                    $"[{_stepType}] Requested index {targetIndex} is not future (current: {currentIndex}) and not cached."));

        byte[]? chainKeyBytes = null;
        try
        {
            chainKeyBytes = _chainKeyHandle.ReadBytes(Constants.X25519KeySize).Unwrap();

            Span<byte> currentChainKey = stackalloc byte[Constants.X25519KeySize];
            chainKeyBytes.CopyTo(currentChainKey);

            Span<byte> nextChainKey = stackalloc byte[Constants.X25519KeySize];
            Span<byte> msgKey = stackalloc byte[Constants.AesKeySize];

            for (uint idx = currentIndex + 1; idx <= targetIndex; idx++)
            {
                try
                {
                    System.Security.Cryptography.HKDF.DeriveKey(
                        System.Security.Cryptography.HashAlgorithmName.SHA256,
                        ikm: currentChainKey,
                        output: msgKey,
                        salt: null,
                        info: MsgInfo
                    );

                    System.Security.Cryptography.HKDF.DeriveKey(
                        System.Security.Cryptography.HashAlgorithmName.SHA256,
                        ikm: currentChainKey,
                        output: nextChainKey,
                        salt: null,
                        info: ChainInfo
                    );
                }
                catch (Exception ex)
                {
                    return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.DeriveKey($"HKDF failed during derivation at index {idx}.", ex));
                }

                Result<RatchetChainKey, EcliptixProtocolFailure> keyResult = RatchetChainKey.New(idx, msgKey);
                if (keyResult.IsErr)
                    return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(keyResult.UnwrapErr());

                RatchetChainKey messageKey = keyResult.Unwrap();

                if (!_messageKeys.TryAdd(idx, messageKey))
                {
                    messageKey.Dispose();
                    return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"Key for index {idx} unexpectedly appeared during derivation."));
                }

                Result<Unit, EcliptixProtocolFailure> writeResult =
                    _chainKeyHandle.Write(nextChainKey).MapSodiumFailure();
                if (writeResult.IsErr)
                {
                    _messageKeys.Remove(idx, out RatchetChainKey? removedKey);
                    removedKey?.Dispose();
                    return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(writeResult.UnwrapErr());
                }

                nextChainKey.CopyTo(currentChainKey);
            }

            Result<Unit, EcliptixProtocolFailure> setIndexResult = SetCurrentIndex(targetIndex);
            if (setIndexResult.IsErr)
                return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(setIndexResult.UnwrapErr());

            PruneOldKeys();

            if (_messageKeys.TryGetValue(targetIndex, out RatchetChainKey? finalKey))
            {
                return Result<RatchetChainKey, EcliptixProtocolFailure>.Ok(finalKey);
            }
            else
            {
                return Result<RatchetChainKey, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(
                        $"Derived key for index {targetIndex} missing after derivation loop."));
            }
        }
        finally
        {
            if (chainKeyBytes != null) SodiumInterop.SecureWipe(chainKeyBytes).IgnoreResult();
        }
    }

    internal Result<Unit, EcliptixProtocolFailure> UpdateKeysAfterDhRatchet(byte[] newChainKey,
        byte[]? newDhPrivateKey = null, byte[]? newDhPublicKey = null)
    {
        if (_disposed)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolChainStep)));
        if (newChainKey.Length != Constants.X25519KeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("New chain key has incorrect size."));

        _chainKeyHandle.Write(newChainKey).Unwrap();

        SetCurrentIndex(0).Unwrap();

        return HandleDhKeyUpdate(newDhPrivateKey, newDhPublicKey);
    }

    internal Result<byte[]?, EcliptixProtocolFailure> ReadDhPublicKey()
    {
        return CheckDisposed().Map<byte[]?>(_ => (byte[]?)_dhPublicKey?.Clone());
    }

    internal void PruneOldKeys()
    {
        if (_disposed || _cacheWindow == 0 || _messageKeys.Count == 0) return;

        uint minIndexToKeep = _currentIndex >= _cacheWindow ? _currentIndex - _cacheWindow + 1 : 0;
        List<uint> keysToRemove = _messageKeys.Keys.Where(k => k < minIndexToKeep).ToList();

        foreach (uint keyIndex in keysToRemove)
        {
            if (_messageKeys.Remove(keyIndex, out RatchetChainKey? messageKeyToDispose))
            {
                messageKeyToDispose?.Dispose();
            }
        }
    }

    public Result<ChainStepState, EcliptixProtocolFailure> ToProtoState()
    {
        if (_disposed)
            return Result<ChainStepState, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolChainStep)));

        byte[]? chainKey = null;
        byte[]? dhPrivKey = null;
        try
        {
            chainKey = _chainKeyHandle.ReadBytes(Constants.X25519KeySize).Unwrap();
            dhPrivKey = _dhPrivateKeyHandle?.ReadBytes(Constants.X25519PrivateKeySize).Unwrap();

            ChainStepState proto = new()
            {
                CurrentIndex = _currentIndex,
                ChainKey = ByteString.CopyFrom(chainKey.AsSpan()),
            };

            if (dhPrivKey != null) proto.DhPrivateKey = ByteString.CopyFrom(dhPrivKey.AsSpan());
            if (_dhPublicKey != null) proto.DhPublicKey = ByteString.CopyFrom(_dhPublicKey.AsSpan());

            foreach (KeyValuePair<uint, RatchetChainKey> kvp in _messageKeys)
            {
                byte[]? keyMaterial = null;
                try
                {
                    keyMaterial = ArrayPool<byte>.Shared.Rent(Constants.AesKeySize);
                    Result<Unit, EcliptixProtocolFailure> readResult = kvp.Value.ReadKeyMaterial(keyMaterial.AsSpan(0, Constants.AesKeySize));
                    if (readResult.IsErr)
                    {
                        continue;
                    }

                    proto.CachedMessageKeys.Add(new CachedMessageKey
                    {
                        Index = kvp.Key,
                        KeyMaterial = ByteString.CopyFrom(keyMaterial.AsSpan(0, Constants.AesKeySize))
                    });
                }
                finally
                {
                    if (keyMaterial != null)
                    {
                        ArrayPool<byte>.Shared.Return(keyMaterial, clearArray: true);
                    }
                }
            }

            return Result<ChainStepState, EcliptixProtocolFailure>.Ok(proto);
        }
        finally
        {
            SodiumInterop.SecureWipe(chainKey).IgnoreResult();
            SodiumInterop.SecureWipe(dhPrivKey).IgnoreResult();
        }
    }

    public static Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> Create(
        RatchetChainStepType stepType,
        byte[] initialChainKey,
        byte[]? initialDhPrivateKey,
        byte[]? initialDhPublicKey,
        uint cacheWindowSize = DefaultCacheWindowSize)
    {
        if (initialChainKey.Length != Constants.X25519KeySize)
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Initial chain key has incorrect size."));

        if ((initialDhPrivateKey == null) != (initialDhPublicKey == null))
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput(
                    "DH private and public keys must both be provided, or neither."));

        if (initialDhPrivateKey != null && initialDhPrivateKey.Length != Constants.X25519PrivateKeySize)
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Initial DH private key has incorrect size."));

        if (initialDhPublicKey != null && initialDhPublicKey.Length != Constants.X25519PublicKeySize)
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Initial DH public key has incorrect size."));

        SodiumSecureMemoryHandle? chainKeyHandle = null;
        SodiumSecureMemoryHandle? dhPrivateKeyHandle = null;

        try
        {
            chainKeyHandle = SodiumSecureMemoryHandle.Allocate(initialChainKey.Length).Unwrap();
            chainKeyHandle.Write(initialChainKey).Unwrap();

            if (initialDhPrivateKey != null)
            {
                dhPrivateKeyHandle = SodiumSecureMemoryHandle.Allocate(initialDhPrivateKey.Length).Unwrap();
                dhPrivateKeyHandle.Write(initialDhPrivateKey).Unwrap();
            }

            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Ok(
                new EcliptixProtocolChainStep(stepType, chainKeyHandle, dhPrivateKeyHandle,
                    (byte[]?)initialDhPublicKey?.Clone(), cacheWindowSize));
        }
        catch (Exception ex)
        {
            chainKeyHandle?.Dispose();
            dhPrivateKeyHandle?.Dispose();
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to create EcliptixProtocolChainStep.", ex));
        }
    }

    private Result<Unit, EcliptixProtocolFailure> CheckDisposed() =>
        _disposed
            ? Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolChainStep)))
            : OkResult;

    private Result<Unit, EcliptixProtocolFailure> HandleDhKeyUpdate(byte[]? newDhPrivateKey, byte[]? newDhPublicKey)
    {
        _messageKeys.Clear();

        if (newDhPrivateKey == null && newDhPublicKey == null)
        {
            return OkResult;
        }

        if (newDhPrivateKey == null != (newDhPublicKey == null))
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Both new DH keys must be provided or neither."));

        if (newDhPrivateKey!.Length != Constants.X25519PrivateKeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("New DH private key has incorrect size."));

        if (newDhPublicKey!.Length != Constants.X25519KeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("New DH public key has incorrect size."));

        SodiumSecureMemoryHandle? newDhPrivateHandle = null;
        try
        {
            newDhPrivateHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize).Unwrap();
            newDhPrivateHandle.Write(newDhPrivateKey).Unwrap();

            _dhPrivateKeyHandle?.Dispose();
            _dhPrivateKeyHandle = newDhPrivateHandle;
            newDhPrivateHandle = null;

            SodiumInterop.SecureWipe(_dhPublicKey).IgnoreResult();
            _dhPublicKey = (byte[])newDhPublicKey.Clone();

            return OkResult;
        }
        finally
        {
            newDhPrivateHandle?.Dispose();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _chainKeyHandle.Dispose();
        _dhPrivateKeyHandle?.Dispose();
        SodiumInterop.SecureWipe(_dhPublicKey).IgnoreResult();
        foreach (KeyValuePair<uint, RatchetChainKey> kvp in _messageKeys)
        {
            kvp.Value.Dispose();
        }

        _messageKeys.Clear();
        _disposed = true;
    }
}