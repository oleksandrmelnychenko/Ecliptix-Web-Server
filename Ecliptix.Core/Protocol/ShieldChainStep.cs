using Sodium;
using System;
using Ecliptix.Core.Protocol.Utilities;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldChainStep : IDisposable
{
    private const uint DefaultCacheWindowSize = 1000;

    private readonly ChainStepType _stepType;
    private readonly uint _cacheWindow;
    private SodiumSecureMemoryHandle _chainKeyHandle;
    private SodiumSecureMemoryHandle? _dhPrivateKeyHandle; // Nullable for sending chain
    private byte[]? _dhPublicKey; // Nullable for sending chain

    private uint _currentIndex;
    private DateTimeOffset _lastUpdate;
    private bool _disposed;
    public bool IsNewChain { get; set; }

    public ChainStepType StepType => _stepType;

    public uint CurrentIndex
    {
        get => _disposed ? throw new ObjectDisposedException(nameof(ShieldChainStep)) : _currentIndex;
        internal set
        {
            if (_disposed) throw new ObjectDisposedException(nameof(ShieldChainStep));
            if (_currentIndex != value)
            {
                Console.WriteLine($"[{_stepType}] Updating CurrentIndex from {_currentIndex} to {value}");
                _currentIndex = value;
                _lastUpdate = DateTimeOffset.UtcNow;
            }
            else
            {
                _currentIndex = value;
            }
        }
    }

    /// <summary>
    /// Initializes a chain step for sending or receiving.
    /// - Sending chain: DH keys can be null (ephemeral keys generated later).
    /// - Receiving chain: Requires valid DH keys (persistent).
    /// </summary>
    internal ShieldChainStep(ChainStepType stepType, byte[] initialChainKey, byte[]? initialDhPrivateKey,
        byte[]? initialDhPublicKey, uint cacheWindowSize = DefaultCacheWindowSize)
    {
        if (initialChainKey == null || initialChainKey.Length != Constants.X25519KeySize)
            throw new ArgumentException("Invalid chain key.", nameof(initialChainKey));

        _stepType = stepType;
        _cacheWindow = cacheWindowSize > 0 ? cacheWindowSize : DefaultCacheWindowSize;

        // DH key handling: null allowed for sending chain, both required or neither if provided
        if (initialDhPrivateKey != null && initialDhPublicKey != null)
        {
            if (initialDhPrivateKey.Length != Constants.X25519PrivateKeySize)
                throw new ArgumentException("Invalid DH private key.", nameof(initialDhPrivateKey));
            if (initialDhPublicKey.Length != Constants.X25519KeySize)
                throw new ArgumentException("Invalid DH public key.", nameof(initialDhPublicKey));
            _dhPrivateKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
            _dhPrivateKeyHandle.Write(initialDhPrivateKey);
            _dhPublicKey = (byte[])initialDhPublicKey.Clone();
        }
        else if (initialDhPrivateKey != null || initialDhPublicKey != null)
        {
            throw new ArgumentException("Both DH private and public keys must be provided or neither.");
        }

        _chainKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize);
        _chainKeyHandle.Write(initialChainKey);

        _currentIndex = 0;
        _lastUpdate = DateTimeOffset.UtcNow;
        IsNewChain = false;

        Console.WriteLine(
            $"[{_stepType}] Step Initialized. Index: {_currentIndex}. CK set. DH PK: {(_dhPublicKey != null ? Convert.ToHexString(_dhPublicKey) : "null")}");
    }

    /// <summary>
    /// Derives or retrieves a message key for the target index using HKDF, per Double Ratchet spec.
    /// </summary>
    internal ShieldMessageKey GetOrDeriveKeyFor(uint targetIndex, SortedDictionary<uint, ShieldMessageKey> messageKeys)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ShieldChainStep));
        ArgumentNullException.ThrowIfNull(messageKeys);

        if (messageKeys.TryGetValue(targetIndex, out var cachedKey))
        {
            Console.WriteLine($"[{_stepType}] Found cached key for index {targetIndex}.");
            return cachedKey;
        }

        uint indexBeforeDerivation = CurrentIndex;
        if (targetIndex <= indexBeforeDerivation)
            throw new ShieldChainStepException(
                $"[{_stepType}] Requested index {targetIndex} is not future (current: {indexBeforeDerivation}) and not cached.");

        byte[]? currentChainKey = null;
        byte[]? nextChainKey = null;
        byte[]? msgKey = null;

        try
        {
            currentChainKey = new byte[Constants.X25519KeySize];
            nextChainKey = new byte[Constants.X25519KeySize];
            msgKey = new byte[Constants.AesKeySize];
            _chainKeyHandle.Read(currentChainKey.AsSpan());

            for (uint idx = indexBeforeDerivation + 1; idx <= targetIndex; idx++)
            {
                using HkdfSha256 hkdfMsg = new HkdfSha256(currentChainKey, null);
                hkdfMsg.Expand(Constants.MsgInfo, msgKey.AsSpan());

                using HkdfSha256 hkdfChain = new HkdfSha256(currentChainKey, null);
                hkdfChain.Expand(Constants.ChainInfo, nextChainKey.AsSpan());

                var messageKey = new ShieldMessageKey(idx, msgKey);
                if (!messageKeys.TryAdd(idx, messageKey))
                {
                    messageKey.Dispose();
                    throw new InvalidOperationException($"Key for index {idx} appeared in cache during derivation.");
                }

                _chainKeyHandle.Write(nextChainKey);
                Array.Copy(nextChainKey, currentChainKey, nextChainKey.Length);
            }

            return messageKeys[targetIndex];
        }
        finally
        {
            SodiumInterop.SecureWipe(currentChainKey);
            SodiumInterop.SecureWipe(nextChainKey);
            SodiumInterop.SecureWipe(msgKey);
        }
    }

    /// <summary>
    /// Updates keys after a DH ratchet:
    /// - Sending chain: Updates chain key and optionally ephemeral DH keys.
    /// - Receiving chain: Updates chain key only, retains persistent DH keys.
    /// </summary>
    internal void UpdateKeysAfterDhRatchet(byte[] newChainKey, byte[]? newDhPrivateKey = null,
        byte[]? newDhPublicKey = null)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ShieldChainStep));
        if (newChainKey == null || newChainKey.Length != Constants.X25519KeySize)
            throw new ArgumentException("Invalid chain key.", nameof(newChainKey));

        _chainKeyHandle.Write(newChainKey);
        _currentIndex = 0; // Reset index per Double Ratchet
       

        if (newDhPrivateKey != null && newDhPublicKey != null)
        {
            if (newDhPrivateKey.Length != Constants.X25519PrivateKeySize ||
                newDhPublicKey.Length != Constants.X25519KeySize)
                throw new ArgumentException("Invalid DH key size.");
            if (_dhPrivateKeyHandle == null)
                _dhPrivateKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
            _dhPrivateKeyHandle.Write(newDhPrivateKey);
            WipeIfNotNull(_dhPublicKey);
            _dhPublicKey = (byte[])newDhPublicKey.Clone();
            Console.WriteLine($"[{_stepType}] Updated DH Keys: PK = {Convert.ToHexString(_dhPublicKey)}");
        }
        else if (newDhPrivateKey != null || newDhPublicKey != null)
        {
            throw new ArgumentException("Both DH keys must be provided or neither.");
        }

        _lastUpdate = DateTimeOffset.UtcNow;
        IsNewChain = _stepType == ChainStepType.Sender;
    }

    internal byte[] ReadChainKey() => _disposed
        ? throw new ObjectDisposedException(nameof(ShieldChainStep))
        : _chainKeyHandle.ReadBytes(Constants.X25519KeySize);

    internal byte[]? ReadDhPrivateKey() => _disposed
        ? throw new ObjectDisposedException(nameof(ShieldChainStep))
        : _dhPrivateKeyHandle?.ReadBytes(Constants.X25519PrivateKeySize);

    internal byte[]? ReadDhPublicKey() => _disposed ? throw new ObjectDisposedException(nameof(ShieldChainStep)) :
        _dhPublicKey != null ? (byte[])_dhPublicKey.Clone() : null;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _chainKeyHandle?.Dispose();
        _dhPrivateKeyHandle?.Dispose();
        WipeIfNotNull(_dhPublicKey);
        _chainKeyHandle = null!;
        _dhPrivateKeyHandle = null;
        _dhPublicKey = null;
        GC.SuppressFinalize(this);
    }

    internal void PruneOldKeys(SortedDictionary<uint, ShieldMessageKey> messageKeys)
    {
        if (_cacheWindow == 0 || messageKeys == null || !messageKeys.Any()) return;

        uint indexToPruneAgainst = CurrentIndex;
        uint minIndexToKeep = indexToPruneAgainst >= _cacheWindow ? indexToPruneAgainst - _cacheWindow + 1 : 0;

        var keysToRemove = messageKeys.Keys.Where(k => k < minIndexToKeep).ToList();

        if (keysToRemove.Any())
        {
            Console.WriteLine(
                $"[{_stepType}] Pruning keys older than {minIndexToKeep} (CurrentIndex: {indexToPruneAgainst}). Removing count: {keysToRemove.Count}");
            foreach (var keyIndex in keysToRemove)
            {
                if (messageKeys.Remove(keyIndex, out var messageKeyToDispose))
                {
                    messageKeyToDispose?.Dispose();
                }
            }
        }
    }

    private static void WipeIfNotNull(byte[]? data)
    {
        if (data != null) SodiumInterop.SecureWipe(data);
    }
}