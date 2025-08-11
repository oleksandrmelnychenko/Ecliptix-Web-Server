using System;
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
    private SodiumSecureMemoryHandle _chainKeyHandle;
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
        _chainKeyHandle = chainKeyHandle ?? throw new ArgumentNullException(nameof(chainKeyHandle));
        _dhPrivateKeyHandle = dhPrivateKeyHandle;
        _dhPublicKey = dhPublicKey;
        _cacheWindow = cacheWindowSize > 0 ? cacheWindowSize : DefaultCacheWindowSize;
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
        byte[] chainKeyBytes = proto.ChainKey.ToByteArray();
        byte[]? dhPrivKeyBytes = proto.DhPrivateKey.IsEmpty ? null : proto.DhPrivateKey.ToByteArray();
        byte[]? dhPubKeyBytes = proto.DhPublicKey.IsEmpty ? null : proto.DhPublicKey.ToByteArray();

        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug("[EcliptixProtocolChainStep] Restoring from Proto State (StepType: {StepType}):", stepType);
            Log.Debug("  Current Index: {CurrentIndex}", proto.CurrentIndex);
            Log.Debug("  DH Public Key: {DhPubKey}",
                dhPubKeyBytes != null ? Convert.ToHexString(dhPubKeyBytes) : "<null>");
        }

        Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> createResult =
            Create(stepType, chainKeyBytes, dhPrivKeyBytes, dhPubKeyBytes);
        if (createResult.IsErr)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocolChainStep] Error creating chain step from proto: {Message}",
                    createResult.UnwrapErr().Message);
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
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixProtocolChainStep] Retrieved cached message key for index {TargetIndex}",
                    targetIndex);
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Ok(cachedKey);
        }

        Result<uint, EcliptixProtocolFailure> currentIndexResult = GetCurrentIndex();
        if (currentIndexResult.IsErr)
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(currentIndexResult.UnwrapErr());

        uint currentIndex = currentIndexResult.Unwrap();

        if (targetIndex < currentIndex)
        {
            return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.InvalidInput(
                $"[{_stepType}] Requested index {targetIndex} is not future (current: {currentIndex}) and not cached."));
        }

        byte[]? chainKeyBytes = null;
        try
        {
            chainKeyBytes = _chainKeyHandle.ReadBytes(Constants.X25519KeySize).Unwrap();
            Console.WriteLine($"[SERVER] Starting key derivation for {_stepType} from index {currentIndex + 1} to {targetIndex}");
            Console.WriteLine($"[SERVER] Initial chain key: {Convert.ToHexString(chainKeyBytes)}");

            Span<byte> currentChainKey = stackalloc byte[Constants.X25519KeySize];
            chainKeyBytes.CopyTo(currentChainKey);

            Span<byte> nextChainKey = stackalloc byte[Constants.X25519KeySize];
            Span<byte> msgKey = stackalloc byte[Constants.AesKeySize];

            for (uint idx = currentIndex + 1; idx <= targetIndex; idx++)
            {
                using HkdfSha256 hkdfMsg = new(currentChainKey, null);
                hkdfMsg.Expand(Constants.MsgInfo, msgKey);
                Console.WriteLine($"[SERVER] Derived message key for {_stepType} index {idx}: {Convert.ToHexString(msgKey)}");

                using HkdfSha256 hkdfChain = new(currentChainKey, null);
                hkdfChain.Expand(Constants.ChainInfo, nextChainKey);
                Console.WriteLine($"[SERVER] Next chain key for {_stepType}: {Convert.ToHexString(nextChainKey)}");

                Result<EcliptixMessageKey, EcliptixProtocolFailure> keyResult = EcliptixMessageKey.New(idx, msgKey);
                if (keyResult.IsErr)
                    return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(keyResult.UnwrapErr());

                EcliptixMessageKey messageKey = keyResult.Unwrap();

                if (!_messageKeys.TryAdd(idx, messageKey))
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
                    _messageKeys.Remove(idx, out EcliptixMessageKey? removedKey);
                    removedKey?.Dispose();
                    return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(writeResult.UnwrapErr());
                }

                nextChainKey.CopyTo(currentChainKey);
            }

            Result<Unit, EcliptixProtocolFailure> setIndexResult = SetCurrentIndex(targetIndex);
            if (setIndexResult.IsErr)
                return Result<EcliptixMessageKey, EcliptixProtocolFailure>.Err(setIndexResult.UnwrapErr());

            PruneOldKeys();

            if (_messageKeys.TryGetValue(targetIndex, out EcliptixMessageKey? finalKey))
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
            if (chainKeyBytes != null) SodiumInterop.SecureWipe(chainKeyBytes).IgnoreResult();
        }
    }

    public Result<Unit, EcliptixProtocolFailure> SkipKeysUntil(uint targetIndex)
    {
        if (_currentIndex >= targetIndex)
        {
            return OkResult;
        }

        for (uint i = _currentIndex + 1; i <= targetIndex; i++)
        {
            Result<EcliptixMessageKey, EcliptixProtocolFailure> keyResult = GetOrDeriveKeyFor(i);
            if (keyResult.IsErr)
            {
                return Result<Unit, EcliptixProtocolFailure>.Err(keyResult.UnwrapErr());
            }
        }

        return SetCurrentIndex(targetIndex);
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
            if (_messageKeys.Remove(keyIndex, out EcliptixMessageKey? messageKeyToDispose))
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
                ChainKey = ByteString.CopyFrom(chainKey),
            };

            if (dhPrivKey != null) proto.DhPrivateKey = ByteString.CopyFrom(dhPrivKey);
            if (_dhPublicKey != null) proto.DhPublicKey = ByteString.CopyFrom(_dhPublicKey);

            return Result<ChainStepState, EcliptixProtocolFailure>.Ok(proto);
        }
        finally
        {
            SodiumInterop.SecureWipe(chainKey).IgnoreResult();
            SodiumInterop.SecureWipe(dhPrivKey).IgnoreResult();
        }
    }

    public static Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> Create(
        ChainStepType stepType,
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
        foreach (KeyValuePair<uint, EcliptixMessageKey> kvp in _messageKeys)
        {
            kvp.Value.Dispose();
        }

        _messageKeys.Clear();
        _disposed = true;
    }
}