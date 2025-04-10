using Ecliptix.Core.Protocol.Utilities;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldChainStep : IDisposable
{
    private const uint DefaultCacheWindowSize = 1000;

    private readonly ChainStepType _stepType;
    private readonly uint _cacheWindow;
    private SodiumSecureMemoryHandle _chainKeyHandle;
    private SodiumSecureMemoryHandle _dhPrivateKeyHandle;
    private byte[] _dhPublicKey;

    private uint _currentIndex;
    private DateTimeOffset _lastUpdate;
    private bool _disposed;

    public ChainStepType StepType => _stepType;

    public uint CurrentIndex
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _currentIndex;
        }
    }

    public uint NextMessageIndex => CurrentIndex + 1;

    public byte[] PublicKeyBytes
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_dhPublicKey == null)
                throw new ObjectDisposedException(GetType().FullName, "Public key data unavailable.");
            return (byte[])_dhPublicKey.Clone();
        }
    }

    internal SodiumSecureMemoryHandle DhPrivateKeyHandle
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _dhPrivateKeyHandle;
        }
    }

    internal ShieldChainStep(ChainStepType stepType, byte[] initialChainKey, byte[] initialDhPrivateKey,
        byte[] initialDhPublicKey, uint cacheWindowSize = DefaultCacheWindowSize)
    {
        if (initialChainKey == null || initialChainKey.Length != Constants.X25519KeySize)
            throw new ArgumentException("Invalid chain key.", nameof(initialChainKey));
        if (initialDhPrivateKey == null || initialDhPrivateKey.Length != Constants.X25519PrivateKeySize)
            throw new ArgumentException("Invalid DH private key.", nameof(initialDhPrivateKey));
        if (initialDhPublicKey == null || initialDhPublicKey.Length != Constants.X25519KeySize)
            throw new ArgumentException("Invalid DH public key.", nameof(initialDhPublicKey));

        _stepType = stepType;
        _cacheWindow = cacheWindowSize;
        _dhPublicKey = (byte[])initialDhPublicKey.Clone();

        _chainKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize);
        _dhPrivateKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);

        bool success = false;
        try
        {
            _chainKeyHandle.Write(initialChainKey);
            _dhPrivateKeyHandle.Write(initialDhPrivateKey);
            success = true;
        }
        finally
        {
            if (!success)
            {
                Dispose();
            }
        }

        _currentIndex = 0;
        _lastUpdate = DateTimeOffset.UtcNow;
        Console.WriteLine(
            $"[{_stepType}] Step Initialized. Index: {_currentIndex}. CK set. DH PK set: {Convert.ToHexString(_dhPublicKey)}");
    }

    internal void PruneOldKeys(SortedDictionary<uint, ShieldMessageKey> messageKeys)
    {
        if (_cacheWindow == 0 || messageKeys == null || !messageKeys.Any()) return;
        uint minIndexToKeep = (_currentIndex >= _cacheWindow) ? _currentIndex - _cacheWindow + 1 : 0;
        var keysToRemove = messageKeys.Keys.Where(k => k < minIndexToKeep).ToList();
        foreach (var keyIndex in keysToRemove)
        {
            if (messageKeys.Remove(keyIndex, out var messageKeyToDispose))
            {
                messageKeyToDispose?.Dispose();
            }
        }
    }

    internal void UpdateCurrentIndex(uint newIndex)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (newIndex > _currentIndex)
        {
            Console.WriteLine(
                $"[{_stepType}] Updating Current Index from {_currentIndex} to {newIndex} (Skipped messages)");
            _currentIndex = newIndex;
            _lastUpdate = DateTimeOffset.UtcNow;
        }
    }

    internal void UpdateKeysAfterDhRatchet(byte[] newChainKey, byte[]? newDhPrivateKey = null,
        byte[]? newDhPublicKey = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (newChainKey is not { Length: Constants.X25519KeySize })
            throw new ArgumentException("New chain key invalid.", nameof(newChainKey));

        Console.WriteLine(
            $"[{_stepType}] Updating after DH Ratchet. Old Index: {_currentIndex}. Resetting Index to 0.");
        _chainKeyHandle.Write(newChainKey);
        _currentIndex = 0;

        if (newDhPrivateKey != null && newDhPublicKey != null)
        {
            if (newDhPrivateKey.Length != Constants.X25519PrivateKeySize)
                throw new ArgumentException("Invalid new DH private key.", nameof(newDhPrivateKey));
            if (newDhPublicKey.Length != Constants.X25519KeySize)
                throw new ArgumentException("Invalid new DH public key.", nameof(newDhPublicKey));

            Console.WriteLine($"[{_stepType}] Updating own DH Key Pair.");
            _dhPrivateKeyHandle.Write(newDhPrivateKey);
            if (_dhPublicKey != null) SodiumInterop.SecureWipe(_dhPublicKey);
            _dhPublicKey = (byte[])newDhPublicKey.Clone();
            Console.WriteLine($"[{_stepType}] New DH Public Key: {Convert.ToHexString(_dhPublicKey)}");
        }
        else if (newDhPrivateKey != null || newDhPublicKey != null)
        {
            throw new ArgumentException("Must provide both private and public DH keys, or neither.");
        }

        _lastUpdate = DateTimeOffset.UtcNow;
    }

    public ShieldMessageKey GetOrDeriveKeyFor(uint targetIndex, SortedDictionary<uint, ShieldMessageKey> messageKeys)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (messageKeys.TryGetValue(targetIndex, out var cachedKey))
        {
            return cachedKey;
        }

        if (targetIndex <= _currentIndex)
        {
            throw new ShieldChainStepException(
                $"[{_stepType}] Requested index {targetIndex} is not future (current index: {_currentIndex}) and not found in cache. Cannot re-derive past keys.");
        }

        if (targetIndex > _currentIndex + 1)
        {
            Console.WriteLine(
                $"[WARN][{_stepType}] Deriving key for future index {targetIndex} from {(_currentIndex + 1)}, implying skipped messages. Session should ideally call UpdateCurrentIndex first.");
        }

        Span<byte> currentChainKeySpan = stackalloc byte[Constants.X25519KeySize];
        Span<byte> nextChainKeySpan = stackalloc byte[Constants.X25519KeySize];
        Span<byte> msgKeySpan = stackalloc byte[Constants.AesKeySize];

        try
        {
            _chainKeyHandle.Read(currentChainKeySpan);

            for (uint idx = _currentIndex + 1; idx <= targetIndex; idx++)
            {
                using (HkdfSha256 hkdfMsg = new(currentChainKeySpan, default))
                {
                    hkdfMsg.Expand(Constants.MsgInfo, msgKeySpan);
                }

                using (HkdfSha256 hkdfChain = new(currentChainKeySpan, default))
                {
                    hkdfChain.Expand(Constants.ChainInfo, nextChainKeySpan);
                }

                var messageKey = new ShieldMessageKey(idx, msgKeySpan);
                if (!messageKeys.TryAdd(idx, messageKey))
                {
                    messageKey.Dispose();
                    throw new InvalidOperationException(
                        $"Key for index {idx} appeared in cache during derivation loop.");
                }

                _chainKeyHandle.Write(nextChainKeySpan);
                nextChainKeySpan.CopyTo(currentChainKeySpan);
                _currentIndex = idx;
            }

            _lastUpdate = DateTimeOffset.UtcNow;
            PruneOldKeys(messageKeys);
            return messageKeys[targetIndex];
        }
        catch (Exception ex) when (ex is not ShieldChainStepException)
        {
            currentChainKeySpan.Clear();
            nextChainKeySpan.Clear();
            msgKeySpan.Clear();
            throw new ShieldChainStepException(
                $"[{_stepType}] Key derivation loop failed. Target: {targetIndex}, Current: {_currentIndex}. Error: {ex.Message}",
                ex);
        }
        finally
        {
            currentChainKeySpan.Clear();
            nextChainKeySpan.Clear();
            msgKeySpan.Clear();
        }
    }

    // Added ReadChainKey method
    internal byte[] ReadChainKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] chainKey = new byte[Constants.X25519KeySize];
        _chainKeyHandle.Read(chainKey.AsSpan());
        return chainKey;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _chainKeyHandle?.Dispose();
        _dhPrivateKeyHandle?.Dispose();

        if (_dhPublicKey != null)
        {
            SodiumInterop.SecureWipe(_dhPublicKey);
            _dhPublicKey = null!;
        }

        _chainKeyHandle = null!;
        _dhPrivateKeyHandle = null!;

        GC.SuppressFinalize(this);
    }
}