using Ecliptix.Core.Protocol.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.ProtocolState;
using Google.Protobuf;
using Serilog;
using Serilog.Events;

namespace Ecliptix.Core.Protocol;

public sealed class EcliptixProtocolChainStep : IDisposable
{
    private const uint DefaultCacheWindowSize = 1000;

    private static readonly Result<Unit, EcliptixProtocolFailure> OkResult =
        Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);

    private readonly uint _cacheWindow;
    private readonly ChainStepType _stepType;
    private readonly SodiumSecureMemoryHandle _chainKeyHandle;
    private uint _currentIndex;
    private SodiumSecureMemoryHandle? _dhPrivateKeyHandle;
    private byte[]? _dhPublicKey;
    private bool _disposed;

    private readonly SortedDictionary<uint, EcliptixMessageKey> _messageKeys;
    
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
        _messageKeys = new SortedDictionary<uint, EcliptixMessageKey>();
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

    public static Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> FromProtoState(ChainStepType stepType,
        ChainStepState proto)
    {
        byte[]? chainKeyBytes = proto.ChainKey.ToByteArray();
        byte[]? dhPrivKeyBytes = proto.DhPrivateKey.ToByteArray();
        byte[]? dhPubKeyBytes = proto.DhPublicKey.ToByteArray();

        // Log restored keys
        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug("[EcliptixProtocolChainStep] Restoring from Proto State (StepType: {StepType}):", stepType);
            Log.Debug("  Chain Key: {ChainKey}", Convert.ToHexString(chainKeyBytes));
            Log.Debug("  DH Private Key: {DhPrivKey}", dhPrivKeyBytes != null ? Convert.ToHexString(dhPrivKeyBytes) : "<null>");
            Log.Debug("  DH Public Key: {DhPubKey}", dhPubKeyBytes != null ? Convert.ToHexString(dhPubKeyBytes) : "<null>");
            Log.Debug("  Current Index: {CurrentIndex}", proto.CurrentIndex);
        }

        Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> createResult =
            Create(stepType, chainKeyBytes, dhPrivKeyBytes, dhPubKeyBytes);
        if (createResult.IsErr)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocolChainStep] Error creating chain step from proto: {Message}", createResult.UnwrapErr().Message);
            return createResult;
        }

        EcliptixProtocolChainStep chainStep = createResult.Unwrap();
        chainStep.SetCurrentIndex(proto.CurrentIndex)
            .Unwrap();

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

    internal Result<EcliptixMessageKey, EcliptixProtocolFailure> GetOrDeriveKeyFor(uint targetIndex)
    {
        if (_disposed)
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolChainStep)));

        if (_messageKeys.TryGetValue(targetIndex, out EcliptixMessageKey? cachedKey))
        {
            // Log cached message key retrieval
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocolChainStep] Retrieved cached message key for index {TargetIndex}", targetIndex);
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Ok(cachedKey);
        }

        uint currentIndex = _currentIndex;
        if (targetIndex <= currentIndex)
        {
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.InvalidInput(
                $"[{_stepType}] Requested index {targetIndex} is not future (current: {currentIndex}) and not cached."));
        }

        byte[]? chainKeyBytes = null;
        try
        {
            chainKeyBytes = _chainKeyHandle.ReadBytes(Constants.X25519KeySize).Unwrap();
            // Log initial chain key
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocolChainStep] Current Chain Key at index {CurrentIndex}: {ChainKey}", currentIndex, Convert.ToHexString(chainKeyBytes));

            Span<byte> currentChainKey = stackalloc byte[Constants.X25519KeySize];
            chainKeyBytes.CopyTo(currentChainKey);

            Span<byte> nextChainKey = stackalloc byte[Constants.X25519KeySize];
            Span<byte> msgKey = stackalloc byte[Constants.AesKeySize];

            for (uint idx = currentIndex + 1; idx <= targetIndex; idx++)
            {
                using (HkdfSha256 hkdfMsg = new(currentChainKey, null))
                {
                    hkdfMsg.Expand(Constants.MsgInfo, msgKey);
                }

                using (HkdfSha256 hkdfChain = new(currentChainKey, null))
                {
                    hkdfChain.Expand(Constants.ChainInfo, nextChainKey);
                }

                EcliptixMessageKey messageKey = EcliptixMessageKey.New(idx, msgKey).Unwrap();
                if (!_messageKeys.TryAdd(idx, messageKey))
                {
                    messageKey.Dispose();
                    return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"Key for index {idx} unexpectedly appeared during derivation."));
                }

                nextChainKey.CopyTo(currentChainKey);
                // Log updated chain key
                byte[] tempChainKey = new byte[Constants.X25519KeySize];
                if (_chainKeyHandle.Write(nextChainKey).IsOk)
                {
                    if (_chainKeyHandle.Read(tempChainKey).IsOk)
                    {
                        if (Log.IsEnabled(LogEventLevel.Debug))
                            Log.Debug("[EcliptixProtocolChainStep] Updated Chain Key at index {Idx}: {ChainKey}", idx, Convert.ToHexString(tempChainKey));
                    }
                }
            }

            _chainKeyHandle.Write(currentChainKey).Unwrap();
            SetCurrentIndex(targetIndex).Unwrap();
            PruneOldKeys();

            // Log message key cache
            if (Log.IsEnabled(LogEventLevel.Debug))
            {
                Log.Debug("[EcliptixProtocolChainStep] Message Keys Cache after derivation (Count: {Count}):", _messageKeys.Count);
                foreach (var kvp in _messageKeys)
                {
                    byte[] msgKeyTemp = new byte[Constants.AesKeySize];
                    if (kvp.Value.ReadKeyMaterial(msgKeyTemp).IsOk)
                    {
                        Log.Debug("  Index {Key}: {MsgKey}", kvp.Key, Convert.ToHexString(msgKeyTemp));
                    }
                    else
                    {
                        Log.Debug("  Index {Key}: <Error reading key or disposed>", kvp.Key);
                    }
                }
            }

            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Ok(_messageKeys[targetIndex]);
        }
        catch (Exception ex)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocolChainStep] Error during key derivation: {Message}", ex.Message);
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.DeriveKey($"HKDF failed during derivation loop.", ex));
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
        // Log updated chain key
        if (Log.IsEnabled(LogEventLevel.Debug))
            Log.Debug("[EcliptixProtocolChainStep] Updated Chain Key after DH Ratchet: {ChainKey}", Convert.ToHexString(newChainKey));

        SetCurrentIndex(0).Unwrap();

        if (newDhPrivateKey != null && newDhPublicKey != null)
        {
            // Log updated DH keys
            if (Log.IsEnabled(LogEventLevel.Debug))
            {
                Log.Debug("[EcliptixProtocolChainStep] Updated DH Private Key: {DhPrivKey}", Convert.ToHexString(newDhPrivateKey));
                Log.Debug("[EcliptixProtocolChainStep] Updated DH Public Key: {DhPubKey}", Convert.ToHexString(newDhPublicKey));
            }
        }

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
            if (_messageKeys.Remove(keyIndex, out EcliptixMessageKey? messageKeyToDispose))
            {
                messageKeyToDispose.Dispose();
            }
        }

        // Log message key cache after pruning
        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug("[EcliptixProtocolChainStep] Message Keys Cache after pruning (Count: {Count}):", _messageKeys.Count);
            foreach (var kvp in _messageKeys)
            {
                byte[] msgKeyTemp = new byte[Constants.AesKeySize];
                if (kvp.Value.ReadKeyMaterial(msgKeyTemp).IsOk)
                {
                    Log.Debug("  Index {Key}: {MsgKey}", kvp.Key, Convert.ToHexString(msgKeyTemp));
                }
                else
                {
                    Log.Debug("  Index {Key}: <Error reading key or disposed>", kvp.Key);
                }
            }
        }
    }

    public Result<ChainStepState, EcliptixProtocolFailure> ToProtoState()
    {
        if (_disposed)
            return Result<ChainStepState, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixProtocolChainStep)));

        try
        {
            byte[] chainKey = _chainKeyHandle.ReadBytes(Constants.X25519KeySize).Unwrap();
            byte[]? dhPrivKey = _dhPrivateKeyHandle?.ReadBytes(Constants.X25519PrivateKeySize).Unwrap();

            // Log keys when exporting to proto state
            if (Log.IsEnabled(LogEventLevel.Debug))
            {
                Log.Debug("[EcliptixProtocolChainStep] Exporting to Proto State:");
                Log.Debug("  Chain Key: {ChainKey}", Convert.ToHexString(chainKey));
                Log.Debug("  DH Private Key: {DhPrivKey}", dhPrivKey != null ? Convert.ToHexString(dhPrivKey) : "<null>");
                Log.Debug("  DH Public Key: {DhPubKey}", _dhPublicKey != null ? Convert.ToHexString(_dhPublicKey) : "<null>");
            }

            ChainStepState proto = new()
            {
                CurrentIndex = _currentIndex,
                ChainKey = ByteString.CopyFrom(chainKey),
            };

            if (dhPrivKey != null) proto.DhPrivateKey = ByteString.CopyFrom(dhPrivKey);
            if (_dhPublicKey != null) proto.DhPublicKey = ByteString.CopyFrom(_dhPublicKey);

            return Result<ChainStepState, EcliptixProtocolFailure>.Ok(proto);
        }
        catch (Exception ex)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocolChainStep] Error exporting to proto state: {Message}", ex.Message);
            return Result<ChainStepState, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to export chain step to proto state.", ex));
        }
    }

    public static Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> Create(
        ChainStepType stepType,
        byte[] initialChainKey,
        byte[]? initialDhPrivateKey,
        byte[]? initialDhPublicKey,
        uint cacheWindowSize = DefaultCacheWindowSize)
    {
        SodiumSecureMemoryHandle? chainKeyHandle = null;
        SodiumSecureMemoryHandle? dhPrivateKeyHandle = null;

        try
        {
            if (initialChainKey.Length != Constants.X25519KeySize)
                return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("Initial chain key has incorrect size."));
            if ((initialDhPrivateKey == null) != (initialDhPublicKey == null))
                return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput(
                        "DH private and public keys must both be provided, or neither."));

            chainKeyHandle = SodiumSecureMemoryHandle.Allocate(initialChainKey.Length).Unwrap();
            chainKeyHandle.Write(initialChainKey).Unwrap();

            // Log initial keys
            if (Log.IsEnabled(LogEventLevel.Debug))
            {
                Log.Debug("[EcliptixProtocolChainStep] Created Chain Key: {ChainKey}", Convert.ToHexString(initialChainKey));
                if (initialDhPrivateKey != null)
                {
                    Log.Debug("[EcliptixProtocolChainStep] Initial DH Private Key: {DhPrivKey}", Convert.ToHexString(initialDhPrivateKey));
                    Log.Debug("[EcliptixProtocolChainStep] Initial DH Public Key: {DhPubKey}", Convert.ToHexString(initialDhPublicKey));
                }
            }

            if (initialDhPrivateKey != null)
            {
                dhPrivateKeyHandle = SodiumSecureMemoryHandle.Allocate(initialDhPrivateKey.Length).Unwrap();
                dhPrivateKeyHandle.Write(initialDhPrivateKey).Unwrap();
            }

            EcliptixProtocolChainStep step = new(stepType, chainKeyHandle, dhPrivateKeyHandle,
                (byte[]?)initialDhPublicKey?.Clone(), cacheWindowSize);

            chainKeyHandle = null;
            dhPrivateKeyHandle = null;

            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>.Ok(step);
        }
        catch (Exception ex)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocolChainStep] Error creating chain step: {Message}", ex.Message);
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
        if (newDhPrivateKey == null && newDhPublicKey == null)
        {
            return OkResult;
        }

        if ((newDhPrivateKey == null) != (newDhPublicKey == null))
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Both new DH keys must be provided or neither."));
        if (newDhPrivateKey!.Length != Constants.X25519PrivateKeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("New DH private key has incorrect size."));
        if (newDhPublicKey!.Length != Constants.X25519KeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("New DH public key has incorrect size."));

        Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> newHandleResult =
            SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize)
                .MapSodiumFailure()
                .Bind(handle =>
                {
                    Result<Unit, SodiumFailure> writeResult = handle.Write(newDhPrivateKey.AsSpan());

                    if (writeResult.IsErr)
                    {
                        handle.Dispose();
                        return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(writeResult.UnwrapErr())
                            .MapSodiumFailure();
                    }

                    return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Ok(handle);
                });

        if (newHandleResult.IsErr)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(newHandleResult.UnwrapErr());
        }

        SodiumSecureMemoryHandle preparedNewHandle = newHandleResult.Unwrap();

        _dhPrivateKeyHandle?.Dispose();
        _dhPrivateKeyHandle = preparedNewHandle;

        WipeIfNotNull(_dhPublicKey).IgnoreResult();
        _dhPublicKey = (byte[])newDhPublicKey.Clone();

        return OkResult;
    }

    private static Result<Unit, EcliptixProtocolFailure> WipeIfNotNull(byte[]? data) =>
        data == null ? OkResult : SodiumInterop.SecureWipe(data).MapSodiumFailure();

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _chainKeyHandle?.Dispose();
        _dhPrivateKeyHandle?.Dispose();
        WipeIfNotNull(_dhPublicKey).IgnoreResult();
    }
}