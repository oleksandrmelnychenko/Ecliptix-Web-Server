using System.Diagnostics;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldChainStep : IDisposable
{
    private const uint DefaultCacheWindowSize = 1000;

    private SodiumSecureMemoryHandle _chainKeyHandle;

    private SodiumSecureMemoryHandle? _dhPrivateKeyHandle;

    private byte[]? _dhPublicKey;

    private uint _currentIndex;

    private bool _disposed;

    private bool _isNewChain;

    private readonly ChainStepType _stepType;

    private readonly uint _cacheWindow;

    private static readonly Result<Unit, ShieldFailure> OkResult = Result<Unit, ShieldFailure>.Ok(Unit.Value);

    public Result<uint, ShieldFailure> GetCurrentIndex() =>
        _disposed
            ? Result<uint, ShieldFailure>.Err(ShieldFailure.ObjectDisposed(nameof(ShieldChainStep)))
            : Result<uint, ShieldFailure>.Ok(_currentIndex);

    internal Result<Unit, ShieldFailure> SetCurrentIndex(uint value)
    {
        if (_disposed)
        {
            return Result<Unit, ShieldFailure>.Err(ShieldFailure.ObjectDisposed(nameof(ShieldChainStep)));
        }

        if (_currentIndex != value)
        {
            Debug.WriteLine($"[ShieldChainStep] Setting current index from {_currentIndex} to {value}");
            _currentIndex = value;
        }

        return Result<Unit, ShieldFailure>.Ok(Unit.Value);
    }

    private ShieldChainStep(
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
        Debug.WriteLine($"[ShieldChainStep] Created chain step of type {_stepType}");
    }

    public static Result<ShieldChainStep, ShieldFailure> Create(
        ChainStepType stepType,
        byte[] initialChainKey,
        byte[]? initialDhPrivateKey,
        byte[]? initialDhPublicKey,
        uint cacheWindowSize = DefaultCacheWindowSize)
    {
        Debug.WriteLine($"[ShieldChainStep] Creating chain step of type {stepType}");
        return Result<Unit, ShieldFailure>.Ok(Unit.Value)
            .Bind(_ => ValidateInitialChainKey(initialChainKey))
            .Bind(_ => ValidateAndPrepareDhKeys(initialDhPrivateKey, initialDhPublicKey))
            .Bind(dhInfo =>
                AllocateAndWriteChainKey(initialChainKey)
                    .Bind(chainKeyHandle =>
                    {
                        uint actualCacheWindow = cacheWindowSize > 0 ? cacheWindowSize : DefaultCacheWindowSize;
                        ShieldChainStep step = new(
                            stepType,
                            chainKeyHandle,
                            dhInfo.dhPrivateKeyHandle,
                            dhInfo.dhPublicKeyCloned,
                            actualCacheWindow);
                        Debug.WriteLine($"[ShieldChainStep] Chain step created successfully.");
                        return Result<ShieldChainStep, ShieldFailure>.Ok(step);
                    })
                    .MapErr(err =>
                    {
                        Debug.WriteLine($"[ShieldChainStep] Error creating chain step: {err.Message}");
                        dhInfo.dhPrivateKeyHandle?.Dispose();
                        WipeIfNotNull(dhInfo.dhPublicKeyCloned).IgnoreResult();
                        return err;
                    })
            );
    }

    private static Result<Unit, ShieldFailure> ValidateInitialChainKey(byte[] initialChainKey) =>
        initialChainKey.Length == Constants.X25519KeySize
            ? Result<Unit, ShieldFailure>.Ok(Unit.Value)
            : Result<Unit, ShieldFailure>.Err(
                ShieldFailure.InvalidInput($"Initial chain key must be {Constants.X25519KeySize} bytes."));

    private static Result<(SodiumSecureMemoryHandle? dhPrivateKeyHandle, byte[]? dhPublicKeyCloned), ShieldFailure>
        ValidateAndPrepareDhKeys(byte[]? initialDhPrivateKey, byte[]? initialDhPublicKey)
    {
        Debug.WriteLine("[ShieldChainStep] Validating and preparing DH keys");
        if (initialDhPrivateKey == null && initialDhPublicKey == null)
        {
            return Result<(SodiumSecureMemoryHandle?, byte[]?), ShieldFailure>.Ok((null, null));
        }

        if (initialDhPrivateKey == null || initialDhPublicKey == null)
        {
            return Result<(SodiumSecureMemoryHandle?, byte[]?), ShieldFailure>.Err(
                ShieldFailure.InvalidInput("Both DH private and public keys must be provided, or neither."));
        }

        if (initialDhPrivateKey.Length != Constants.X25519PrivateKeySize)
        {
            return Result<(SodiumSecureMemoryHandle?, byte[]?), ShieldFailure>.Err(
                ShieldFailure.InvalidInput(
                    $"Initial DH private key must be {Constants.X25519PrivateKeySize} bytes."));
        }

        if (initialDhPublicKey.Length != Constants.X25519KeySize)
        {
            return Result<(SodiumSecureMemoryHandle?, byte[]?), ShieldFailure>.Err(
                ShieldFailure.InvalidInput($"Initial DH public key must be {Constants.X25519KeySize} bytes."));
        }

        SodiumSecureMemoryHandle? dhPrivateKeyHandle = null;
        try
        {
            return SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize)
                .Bind(handle =>
                {
                    dhPrivateKeyHandle = handle;
                    Debug.WriteLine(
                        $"[ShieldChainStep] Writing initial DH private key: {Convert.ToHexString(initialDhPrivateKey)}");
                    return handle.Write(initialDhPrivateKey);
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
            return Result<(SodiumSecureMemoryHandle?, byte[]?), ShieldFailure>.Err(
                ShieldFailure.Generic("Unexpected error preparing DH keys.", ex));
        }
    }

    private static Result<SodiumSecureMemoryHandle, ShieldFailure> AllocateAndWriteChainKey(byte[] initialChainKey)
    {
        SodiumSecureMemoryHandle? chainKeyHandle = null;
        return SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize)
            .Bind(handle =>
            {
                chainKeyHandle = handle;
                Debug.WriteLine($"[ShieldChainStep] Writing initial chain key: {Convert.ToHexString(initialChainKey)}");
                return handle.Write(initialChainKey);
            })
            .Map(_ => chainKeyHandle!)
            .MapErr(err =>
            {
                Debug.WriteLine($"[ShieldChainStep] Error allocating chain key: {err.Message}");
                chainKeyHandle?.Dispose();
                return err;
            });
    }

    internal Result<ShieldMessageKey, ShieldFailure> GetOrDeriveKeyFor(uint targetIndex,
        SortedDictionary<uint, ShieldMessageKey> messageKeys)
    {
        if (_disposed)
            return Result<ShieldMessageKey, ShieldFailure>.Err(ShieldFailure.ObjectDisposed(nameof(ShieldChainStep)));

        if (messageKeys.TryGetValue(targetIndex, out var cachedKey))
        {
            Debug.WriteLine($"[ShieldChainStep] Returning cached key for index {targetIndex}");
            return Result<ShieldMessageKey, ShieldFailure>.Ok(cachedKey);
        }

        Result<uint, ShieldFailure> currentIndexResult = GetCurrentIndex();
        if (currentIndexResult.IsErr)
            return Result<ShieldMessageKey, ShieldFailure>.Err(currentIndexResult.UnwrapErr());

        uint currentIndex = currentIndexResult.Unwrap();

        if (targetIndex <= currentIndex)
            return Result<ShieldMessageKey, ShieldFailure>.Err(
                ShieldFailure.InvalidInput(
                    $"[{_stepType}] Requested index {targetIndex} is not future (current: {currentIndex}) and not cached."));

        Debug.WriteLine(
            $"[ShieldChainStep] Starting derivation for target index: {targetIndex}, current index: {currentIndex}");

        Result<byte[], ShieldFailure> chainKeyResult = _chainKeyHandle.ReadBytes(Constants.X25519KeySize);
        if (chainKeyResult.IsErr)
        {
            return Result<ShieldMessageKey, ShieldFailure>.Err(chainKeyResult.UnwrapErr());
        }

        byte[] chainKey = chainKeyResult.Unwrap();

        try
        {
            Span<byte> currentChainKey = stackalloc byte[Constants.X25519KeySize];
            Span<byte> nextChainKey = stackalloc byte[Constants.X25519KeySize];
            Span<byte> msgKey = stackalloc byte[Constants.AesKeySize];

            chainKey.CopyTo(currentChainKey);

            for (uint idx = currentIndex + 1; idx <= targetIndex; idx++)
            {
                Debug.WriteLine($"[ShieldChainStep] Deriving key for index: {idx}");

                try
                {
                    using HkdfSha256 hkdfMsg = new(currentChainKey, null);
                    hkdfMsg.Expand(Constants.MsgInfo, msgKey);

                    using HkdfSha256 hkdfChain = new(currentChainKey, null);
                    hkdfChain.Expand(Constants.ChainInfo, nextChainKey);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[ShieldChainStep] Error deriving keys at index {idx}: {ex.Message}");
                    return Result<ShieldMessageKey, ShieldFailure>.Err(
                        ShieldFailure.DeriveKey($"HKDF failed during derivation at index {idx}.", ex));
                }

                byte[] msgKeyClone = msgKey.ToArray();

                Result<ShieldMessageKey, ShieldFailure> keyResult = ShieldMessageKey.New(idx, msgKeyClone);
                if (keyResult.IsErr)
                {
                    return Result<ShieldMessageKey, ShieldFailure>.Err(keyResult.UnwrapErr());
                }

                ShieldMessageKey messageKey = keyResult.Unwrap();

                if (!messageKeys.TryAdd(idx, messageKey))
                {
                    messageKey.Dispose();
                    return Result<ShieldMessageKey, ShieldFailure>.Err(
                        ShieldFailure.Generic($"Key for index {idx} unexpectedly appeared during derivation."));
                }

                Result<Unit, ShieldFailure> writeResult = _chainKeyHandle.Write(nextChainKey);
                if (writeResult.IsErr)
                {
                    messageKeys.Remove(idx, out var removedKey);
                    removedKey?.Dispose();
                    return Result<ShieldMessageKey, ShieldFailure>.Err(writeResult.UnwrapErr());
                }

                nextChainKey.CopyTo(currentChainKey);
            }

            Result<Unit, ShieldFailure> setIndexResult = SetCurrentIndex(targetIndex);
            if (setIndexResult.IsErr)
            {
                return Result<ShieldMessageKey, ShieldFailure>.Err(setIndexResult.UnwrapErr());
            }

            PruneOldKeys(messageKeys);

            if (messageKeys.TryGetValue(targetIndex, out var finalKey))
            {
                Debug.WriteLine($"[ShieldChainStep] Derived key for index {targetIndex} successfully.");
                return Result<ShieldMessageKey, ShieldFailure>.Ok(finalKey);
            }
            else
            {
                Debug.WriteLine($"[ShieldChainStep] Derived key for index {targetIndex} not found in cache.");
                return Result<ShieldMessageKey, ShieldFailure>.Err(
                    ShieldFailure.Generic($"Derived key for index {targetIndex} missing after derivation loop."));
            }
        }
        finally
        {
            WipeIfNotNull(chainKey).IgnoreResult();
        }
    }

    internal Result<Unit, ShieldFailure> UpdateKeysAfterDhRatchet(byte[] newChainKey, byte[]? newDhPrivateKey = null,
        byte[]? newDhPublicKey = null)
    {
        Debug.WriteLine($"[ShieldChainStep] Updating keys after DH ratchet for {_stepType}");
        return Result<Unit, ShieldFailure>.Ok(Unit.Value)
            .Bind(_ => CheckDisposed())
            .Bind(_ => ValidateNewChainKey(newChainKey))
            .Bind(_ =>
            {
                Debug.WriteLine($"[ShieldChainStep] Writing new chain key: {Convert.ToHexString(newChainKey)}");
                return _chainKeyHandle.Write(newChainKey);
            })
            .Bind(_ => SetCurrentIndex(0))
            .Bind(_ => HandleDhKeyUpdate(newDhPrivateKey, newDhPublicKey))
            .Map(_ =>
            {
                _isNewChain = _stepType == ChainStepType.Sender;
                Debug.WriteLine($"[ShieldChainStep] Keys updated successfully. IsNewChain: {_isNewChain}");
                return Unit.Value;
            });
    }

    private Result<Unit, ShieldFailure> CheckDisposed() =>
        _disposed
            ? Result<Unit, ShieldFailure>.Err(ShieldFailure.ObjectDisposed(nameof(ShieldChainStep)))
            : Result<Unit, ShieldFailure>.Ok(Unit.Value);

    private static Result<Unit, ShieldFailure> ValidateNewChainKey(byte[] newChainKey) =>
        newChainKey.Length == Constants.X25519KeySize
            ? Result<Unit, ShieldFailure>.Ok(Unit.Value)
            : Result<Unit, ShieldFailure>.Err(
                ShieldFailure.InvalidInput($"New chain key must be {Constants.X25519KeySize} bytes."));

    private Result<Unit, ShieldFailure> HandleDhKeyUpdate(byte[]? newDhPrivateKey, byte[]? newDhPublicKey)
    {
        if (newDhPrivateKey == null && newDhPublicKey == null)
        {
            return OkResult;
        }

        return ValidateAll(
            () => ValidateDhKeysNotNull(newDhPrivateKey, newDhPublicKey),
            () => ValidateDhPrivateKeySize(newDhPrivateKey),
            () => ValidateDhPublicKeySize(newDhPublicKey)
        ).Bind(_ =>
        {
            Debug.WriteLine($"[ShieldChainStep] Updating DH keys.");

            Result<Unit, ShieldFailure> handleResult = EnsureDhPrivateKeyHandle();
            if (handleResult.IsErr)
            {
                return handleResult.MapErr(e => e);
            }

            Result<Unit, ShieldFailure> writeResult = _dhPrivateKeyHandle!.Write(newDhPrivateKey!.AsSpan());
            if (writeResult.IsErr)
            {
                return writeResult.MapErr(e => e);
            }

            WipeIfNotNull(_dhPublicKey).IgnoreResult();
            _dhPublicKey = (byte[])newDhPublicKey!.Clone();

            return OkResult;
        });
    }

    private Result<Unit, ShieldFailure> EnsureDhPrivateKeyHandle()
    {
        if (_dhPrivateKeyHandle != null)
        {
            return OkResult;
        }

        Result<SodiumSecureMemoryHandle, ShieldFailure> allocResult =
            SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
        if (allocResult.IsErr)
        {
            return Result<Unit, ShieldFailure>.Err(allocResult.UnwrapErr());
        }

        _dhPrivateKeyHandle = allocResult.Unwrap();
        return OkResult;
    }

    private static Result<Unit, ShieldFailure> ValidateAll(params Func<Result<Unit, ShieldFailure>>[]? validators)
    {
        if (validators is null || validators.Length == 0)
        {
            return OkResult;
        }

        foreach (Func<Result<Unit, ShieldFailure>> validate in validators)
        {
            Result<Unit, ShieldFailure> result = validate();
            if (result.IsErr)
            {
                return result;
            }
        }

        return OkResult;
    }

    private static Result<Unit, ShieldFailure> ValidateDhKeysNotNull(byte[]? privateKey, byte[]? publicKey)
    {
        if (privateKey == null && publicKey == null)
        {
            return OkResult;
        }

        if (privateKey == null || publicKey == null)
        {
            return Result<Unit, ShieldFailure>.Err(
                ShieldFailure.InvalidInput("Both DH private and public keys must be provided together."));
        }

        return OkResult;
    }

    private static Result<Unit, ShieldFailure> ValidateDhPrivateKeySize(byte[]? privateKey)
    {
        if (privateKey == null)
        {
            return OkResult;
        }

        return privateKey.Length == Constants.X25519PrivateKeySize
            ? OkResult
            : Result<Unit, ShieldFailure>.Err(
                ShieldFailure.InvalidInput($"DH private key must be {Constants.X25519PrivateKeySize} bytes."));
    }

    private static Result<Unit, ShieldFailure> ValidateDhPublicKeySize(byte[]? publicKey)
    {
        if (publicKey == null)
        {
            return OkResult;
        }

        return publicKey.Length == Constants.X25519KeySize
            ? OkResult
            : Result<Unit, ShieldFailure>.Err(
                ShieldFailure.InvalidInput($"DH public key must be {Constants.X25519KeySize} bytes."));
    }

    internal Result<byte[]?, ShieldFailure> ReadDhPublicKey() =>
        CheckDisposed().Map<byte[]?>(_ =>
        {
            byte[]? result = (byte[])_dhPublicKey?.Clone()!;
            Debug.WriteLine(
                $"[ShieldChainStep] Read DH public key: {Convert.ToHexString(result ?? Array.Empty<byte>())}");
            return result;
        });

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Debug.WriteLine($"[ShieldChainStep] Disposing chain step of type {_stepType}");

        _chainKeyHandle?.Dispose();
        _dhPrivateKeyHandle?.Dispose();
        WipeIfNotNull(_dhPublicKey).IgnoreResult();

        _chainKeyHandle = null!;
        _dhPrivateKeyHandle = null;
        _dhPublicKey = null;
    }

    internal void PruneOldKeys(SortedDictionary<uint, ShieldMessageKey> messageKeys)
    {
        if (_disposed || _cacheWindow == 0 || messageKeys.Count == 0) return;

        Result<uint, ShieldFailure> currentIndexResult = GetCurrentIndex();
        if (currentIndexResult.IsErr) return;
        uint indexToPruneAgainst = currentIndexResult.Unwrap();

        uint minIndexToKeep = indexToPruneAgainst >= _cacheWindow ? indexToPruneAgainst - _cacheWindow + 1 : 0;
        Debug.WriteLine(
            $"[ShieldChainStep] Pruning old keys. Current Index: {indexToPruneAgainst}, Min Index to Keep: {minIndexToKeep}");

        List<uint> keysToRemove = messageKeys.Keys.Where(k => k < minIndexToKeep).ToList();
        if (keysToRemove.Count != 0)
        {
            foreach (uint keyIndex in keysToRemove)
            {
                if (messageKeys.Remove(keyIndex, out ShieldMessageKey? messageKeyToDispose))
                {
                    messageKeyToDispose.Dispose();
                    Debug.WriteLine($"[ShieldChainStep] Removed old key at index {keyIndex}");
                }
            }
        }
    }

    private static Result<Unit, ShieldFailure> WipeIfNotNull(byte[]? data) =>
        data == null ? Result<Unit, ShieldFailure>.Ok(Unit.Value) : SodiumInterop.SecureWipe(data);
}