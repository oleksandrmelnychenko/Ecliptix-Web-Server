using System.Diagnostics;
using Ecliptix.Core.Protocol.Failures;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Protocol;

public sealed class EcliptixProtocolChainStep : IDisposable
{
    private const uint DefaultCacheWindowSize = 1000;

    private static readonly Result<Unit, EcliptixProtocolFailure> OkResult =
        Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);

    private readonly uint _cacheWindow;

    private readonly ChainStepType _stepType;

    private SodiumSecureMemoryHandle _chainKeyHandle;

    private uint _currentIndex;

    private SodiumSecureMemoryHandle? _dhPrivateKeyHandle;

    private byte[]? _dhPublicKey;

    private bool _disposed;

    private bool _isNewChain;

    private EcliptixProtocolChainStep(
        ChainStepType stepType,
        SodiumSecureMemoryHandle chainKeyHandle,
        SodiumSecureMemoryHandle? dhPrivateKeyHandle,
        byte[]? dhPublicKey,
        uint cacheWindowSize)
    {
        _stepType = stepType;
        _chainKeyHandle = chainKeyHandle;
        _dhPrivateKeyHandle = dhPrivateKeyHandle;
        _dhPublicKey = dhPublicKey;
        _cacheWindow = cacheWindowSize;
        _currentIndex = 0;
        _isNewChain = false;
        _disposed = false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _chainKeyHandle.Dispose();
        _dhPrivateKeyHandle?.Dispose();
        WipeIfNotNull(_dhPublicKey).IgnoreResult();

        _chainKeyHandle = null!;
        _dhPrivateKeyHandle = null;
        _dhPublicKey = null;
    }

    public Result<uint, EcliptixProtocolFailure> GetCurrentIndex()
    {
        return _disposed
            ? Result<uint, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolChainStep)))
            : Result<uint, EcliptixProtocolFailure>.Ok(_currentIndex);
    }

    internal Result<Unit, EcliptixProtocolFailure> SetCurrentIndex(uint value)
    {
        if (_disposed)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolChainStep)));

        if (_currentIndex != value)
        {
            _currentIndex = value;
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public static Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> Create(
        ChainStepType stepType,
        byte[] initialChainKey,
        byte[]? initialDhPrivateKey,
        byte[]? initialDhPublicKey,
        uint cacheWindowSize = DefaultCacheWindowSize)
    {
        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value)
            .Bind(_ => ValidateInitialChainKey(initialChainKey))
            .Bind(_ => ValidateAndPrepareDhKeys(initialDhPrivateKey, initialDhPublicKey))
            .Bind(dhInfo =>
                AllocateAndWriteChainKey(initialChainKey)
                    .Bind(chainKeyHandle =>
                    {
                        uint actualCacheWindow = cacheWindowSize > 0 ? cacheWindowSize : DefaultCacheWindowSize;
                        EcliptixProtocolChainStep step = new(
                            stepType,
                            chainKeyHandle,
                            dhInfo.dhPrivateKeyHandle,
                            dhInfo.dhPublicKeyCloned,
                            actualCacheWindow);
                        return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Ok(step);
                    })
                    .MapErr(err =>
                    {
                        dhInfo.dhPrivateKeyHandle?.Dispose();
                        WipeIfNotNull(dhInfo.dhPublicKeyCloned).IgnoreResult();
                        return err;
                    })
            );
    }

    private static Result<Unit, EcliptixProtocolFailure> ValidateInitialChainKey(byte[] initialChainKey)
    {
        return initialChainKey.Length == Constants.X25519KeySize
            ? Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value)
            : Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput($"Initial chain key must be {Constants.X25519KeySize} bytes."));
    }

    private static Result<(SodiumSecureMemoryHandle? dhPrivateKeyHandle, byte[]? dhPublicKeyCloned),
            EcliptixProtocolFailure>
        ValidateAndPrepareDhKeys(byte[]? initialDhPrivateKey, byte[]? initialDhPublicKey)
    {
        if (initialDhPrivateKey == null && initialDhPublicKey == null)
            return Result<(SodiumSecureMemoryHandle?, byte[]?), EcliptixProtocolFailure>.Ok((null, null));

        if (initialDhPrivateKey == null || initialDhPublicKey == null)
            return Result<(SodiumSecureMemoryHandle?, byte[]?), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Both DH private and public keys must be provided, or neither."));

        if (initialDhPrivateKey.Length != Constants.X25519PrivateKeySize)
            return Result<(SodiumSecureMemoryHandle?, byte[]?), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput(
                    $"Initial DH private key must be {Constants.X25519PrivateKeySize} bytes."));

        if (initialDhPublicKey.Length != Constants.X25519KeySize)
            return Result<(SodiumSecureMemoryHandle?, byte[]?), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput(
                    $"Initial DH public key must be {Constants.X25519KeySize} bytes."));

        SodiumSecureMemoryHandle? dhPrivateKeyHandle = null;
        try
        {
            return SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize).MapSodiumFailure()
                .Bind(handle =>
                {
                    dhPrivateKeyHandle = handle;
                    Debug.WriteLine(
                        $"[ShieldChainStep] Writing initial DH private key: {Convert.ToHexString(initialDhPrivateKey)}");
                    return handle.Write(initialDhPrivateKey).MapSodiumFailure();
                })
                .Map(_ =>
                {
                    byte[] dhPublicKeyCloned = (byte[])initialDhPublicKey.Clone();
                    Debug.WriteLine(
                        $"[ShieldChainStep] Cloned DH public key: {Convert.ToHexString(dhPublicKeyCloned)}");
                    return (dhPrivateKeyHandle, dhPublicKeyCloned);
                })
                .MapErr(err =>
                {
                    dhPrivateKeyHandle?.Dispose();
                    return err;
                })!;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ShieldChainStep] Unexpected error preparing DH keys: {ex.Message}");
            dhPrivateKeyHandle?.Dispose();
            return Result<(SodiumSecureMemoryHandle?, byte[]?), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Unexpected error preparing DH keys.", ex));
        }
    }

    private static Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> AllocateAndWriteChainKey(
        byte[] initialChainKey)
    {
        SodiumSecureMemoryHandle? chainKeyHandle = null;
        return SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize).MapSodiumFailure()
            .Bind(handle =>
            {
                chainKeyHandle = handle;
                return handle.Write(initialChainKey).MapSodiumFailure();
            })
            .Map(_ => chainKeyHandle!)
            .MapErr(err =>
            {
                chainKeyHandle?.Dispose();
                return err;
            });
    }

    internal Result<EcliptixMessageKey, EcliptixProtocolFailure> GetOrDeriveKeyFor(uint targetIndex,
        SortedDictionary<uint, EcliptixMessageKey> messageKeys)
    {
        if (_disposed)
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolChainStep)));

        if (messageKeys.TryGetValue(targetIndex, out EcliptixMessageKey? cachedKey))
        {
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Ok(cachedKey);
        }

        Result<uint, EcliptixProtocolFailure> currentIndexResult = GetCurrentIndex();
        if (currentIndexResult.IsErr)
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(currentIndexResult.UnwrapErr());

        uint currentIndex = currentIndexResult.Unwrap();

        if (targetIndex <= currentIndex)
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput(
                    $"[{_stepType}] Requested index {targetIndex} is not future (current: {currentIndex}) and not cached."));

        Result<byte[], EcliptixProtocolFailure> chainKeyResult = _chainKeyHandle.ReadBytes(Constants.X25519KeySize)
            .MapSodiumFailure();
        if (chainKeyResult.IsErr)
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(chainKeyResult.UnwrapErr());

        byte[] chainKey = chainKeyResult.Unwrap();

        try
        {
            Span<byte> currentChainKey = stackalloc byte[Constants.X25519KeySize];
            Span<byte> nextChainKey = stackalloc byte[Constants.X25519KeySize];
            Span<byte> msgKey = stackalloc byte[Constants.AesKeySize];

            chainKey.CopyTo(currentChainKey);

            for (uint idx = currentIndex + 1; idx <= targetIndex; idx++)
            {
                try
                {
                    using HkdfSha256 hkdfMsg = new(currentChainKey, null);
                    hkdfMsg.Expand(Constants.MsgInfo, msgKey);

                    using HkdfSha256 hkdfChain = new(currentChainKey, null);
                    hkdfChain.Expand(Constants.ChainInfo, nextChainKey);
                }
                catch (Exception ex)
                {
                    return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.DeriveKey($"HKDF failed during derivation at index {idx}.", ex));
                }

                Result<EcliptixMessageKey, EcliptixProtocolFailure>
                    keyResult = EcliptixMessageKey.New(idx, msgKey);

                if (keyResult.IsErr)
                    return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(keyResult.UnwrapErr());

                EcliptixMessageKey messageKey = keyResult.Unwrap();

                if (!messageKeys.TryAdd(idx, messageKey))
                {
                    messageKey.Dispose();
                    return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"Key for index {idx} unexpectedly appeared during derivation."));
                }

                Result<Unit, EcliptixProtocolFailure> writeResult =
                    _chainKeyHandle.Write(nextChainKey).MapSodiumFailure();
                if (writeResult.IsErr)
                {
                    messageKeys.Remove(idx, out EcliptixMessageKey? removedKey);
                    removedKey?.Dispose();
                    return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(writeResult.UnwrapErr());
                }

                nextChainKey.CopyTo(currentChainKey);
            }

            Result<Unit, EcliptixProtocolFailure> setIndexResult = SetCurrentIndex(targetIndex);
            if (setIndexResult.IsErr)
                return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(setIndexResult.UnwrapErr());

            PruneOldKeys(messageKeys);

            if (messageKeys.TryGetValue(targetIndex, out EcliptixMessageKey? finalKey))
            {
                return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Ok(finalKey);
            }
            else
            {
                return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(
                        $"Derived key for index {targetIndex} missing after derivation loop."));
            }
        }
        finally
        {
            WipeIfNotNull(chainKey).IgnoreResult();
        }
    }

    internal Result<Unit, EcliptixProtocolFailure> UpdateKeysAfterDhRatchet(byte[] newChainKey,
        byte[]? newDhPrivateKey = null,
        byte[]? newDhPublicKey = null)
    {
        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value)
            .Bind(_ => CheckDisposed())
            .Bind(_ => ValidateNewChainKey(newChainKey))
            .Bind(_ => _chainKeyHandle.Write(newChainKey).MapSodiumFailure())
            .Bind(_ => SetCurrentIndex(0))
            .Bind(_ => HandleDhKeyUpdate(newDhPrivateKey, newDhPublicKey))
            .Map(_ =>
            {
                _isNewChain = _stepType == ChainStepType.Sender;
                return Unit.Value;
            });
    }

    private Result<Unit, EcliptixProtocolFailure> CheckDisposed() =>
        _disposed
            ? Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolChainStep)))
            : Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);

    private static Result<Unit, EcliptixProtocolFailure> ValidateNewChainKey(byte[] newChainKey) =>
        newChainKey.Length == Constants.X25519KeySize
            ? Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value)
            : Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput($"New chain key must be {Constants.X25519KeySize} bytes."));


    private Result<Unit, EcliptixProtocolFailure> HandleDhKeyUpdate(byte[]? newDhPrivateKey, byte[]? newDhPublicKey)
    {
        if (newDhPrivateKey == null && newDhPublicKey == null) return OkResult;

        return ValidateAll(
            () => ValidateDhKeysNotNull(newDhPrivateKey, newDhPublicKey),
            () => ValidateDhPrivateKeySize(newDhPrivateKey),
            () => ValidateDhPublicKeySize(newDhPublicKey)
        ).Bind(_ =>
        {
            Result<Unit, EcliptixProtocolFailure> handleResult = EnsureDhPrivateKeyHandle();
            if (handleResult.IsErr) return handleResult.MapErr(e => e);

            Result<Unit, EcliptixProtocolFailure> writeResult = _dhPrivateKeyHandle!.Write(newDhPrivateKey!.AsSpan())
                .MapSodiumFailure();
            if (writeResult.IsErr) return writeResult.MapErr(e => e);

            WipeIfNotNull(_dhPublicKey).IgnoreResult();
            _dhPublicKey = (byte[])newDhPublicKey!.Clone();

            return OkResult;
        });
    }

    private Result<Unit, EcliptixProtocolFailure> EnsureDhPrivateKeyHandle()
    {
        if (_dhPrivateKeyHandle != null) return OkResult;

        Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> allocResult =
            SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize).MapSodiumFailure();
        if (allocResult.IsErr) return Result<Unit, EcliptixProtocolFailure>.Err(allocResult.UnwrapErr());

        _dhPrivateKeyHandle = allocResult.Unwrap();
        return OkResult;
    }

    private static Result<Unit, EcliptixProtocolFailure> ValidateAll(
        params Func<Result<Unit, EcliptixProtocolFailure>>[]? validators)
    {
        if (validators is null || validators.Length == 0) return OkResult;

        foreach (Func<Result<Unit, EcliptixProtocolFailure>> validate in validators)
        {
            Result<Unit, EcliptixProtocolFailure> result = validate();
            if (result.IsErr) return result;
        }

        return OkResult;
    }

    private static Result<Unit, EcliptixProtocolFailure> ValidateDhKeysNotNull(byte[]? privateKey, byte[]? publicKey)
    {
        if (privateKey == null && publicKey == null) return OkResult;

        if (privateKey == null || publicKey == null)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Both DH private and public keys must be provided together."));

        return OkResult;
    }

    private static Result<Unit, EcliptixProtocolFailure> ValidateDhPrivateKeySize(byte[]? privateKey)
    {
        if (privateKey == null) return OkResult;

        return privateKey.Length == Constants.X25519PrivateKeySize
            ? OkResult
            : Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput(
                    $"DH private key must be {Constants.X25519PrivateKeySize} bytes."));
    }

    private static Result<Unit, EcliptixProtocolFailure> ValidateDhPublicKeySize(byte[]? publicKey)
    {
        if (publicKey == null) return OkResult;

        return publicKey.Length == Constants.X25519KeySize
            ? OkResult
            : Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput($"DH public key must be {Constants.X25519KeySize} bytes."));
    }

    internal Result<byte[]?, EcliptixProtocolFailure> ReadDhPublicKey()
    {
        return CheckDisposed().Map<byte[]?>(_ =>
        {
            byte[] result = (byte[])_dhPublicKey?.Clone()!;
            return result;
        });
    }

    internal void PruneOldKeys(SortedDictionary<uint, EcliptixMessageKey> messageKeys)
    {
        if (_disposed || _cacheWindow == 0 || messageKeys.Count == 0) return;

        Result<uint, EcliptixProtocolFailure> currentIndexResult = GetCurrentIndex();
        if (currentIndexResult.IsErr) return;
        uint indexToPruneAgainst = currentIndexResult.Unwrap();

        uint minIndexToKeep = indexToPruneAgainst >= _cacheWindow ? indexToPruneAgainst - _cacheWindow + 1 : 0;

        List<uint> keysToRemove = messageKeys.Keys.Where(k => k < minIndexToKeep).ToList();
        if (keysToRemove.Count != 0)
        {
            foreach (uint keyIndex in keysToRemove)
            {
                if (messageKeys.Remove(keyIndex, out EcliptixMessageKey? messageKeyToDispose))
                {
                    messageKeyToDispose.Dispose();
                }
            }
        }
    }

    private static Result<Unit, EcliptixProtocolFailure> WipeIfNotNull(byte[]? data) =>
        data == null
            ? Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value)
            : SodiumInterop.SecureWipe(data).MapSodiumFailure();
}