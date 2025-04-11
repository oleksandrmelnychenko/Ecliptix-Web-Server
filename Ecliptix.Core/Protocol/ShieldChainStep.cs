using Ecliptix.Core.Protocol.Utilities;
using Sodium;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldChainStep : IDisposable
{
    private const uint DefaultCacheWindowSize = 1000; // Or your desired default

    private readonly ChainStepType _stepType;
    private readonly uint _cacheWindow;
    private SodiumSecureMemoryHandle _chainKeyHandle;
    private SodiumSecureMemoryHandle _dhPrivateKeyHandle;
    private byte[] _dhPublicKey; // Only store public key bytes

    private uint _currentIndex;
    private DateTimeOffset _lastUpdate;
    private bool _disposed;
    public bool IsNewChain { get; set; } // Consider if this is actually used

    public ChainStepType StepType => _stepType;

    public uint CurrentIndex
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _currentIndex;
        }
        // Allow ShieldSession to set the index explicitly
        internal set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            // Optional: Add logging only if value changes, reduces noise
            if (_currentIndex != value)
            {
                Console.WriteLine($"[{_stepType}] Updating CurrentIndex from {_currentIndex} to {value}");
                _currentIndex = value;
                _lastUpdate = DateTimeOffset.UtcNow;
            }
            else
            {
                _currentIndex = value; // Still update if same value is set (e.g., after reset)
            }
        }
    }

    // Removed NextMessageIndex property as it's trivial (CurrentIndex + 1)

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
        _cacheWindow = cacheWindowSize > 0 ? cacheWindowSize : DefaultCacheWindowSize; // Ensure positive cache window
        _dhPublicKey = (byte[])initialDhPublicKey.Clone(); // Store only public key

        // Use temporary handles to ensure disposal on failure
        SodiumSecureMemoryHandle? tempChainKeyHandle = null;
        SodiumSecureMemoryHandle? tempDhPrivateKeyHandle = null;

        try
        {
            tempChainKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize);
            tempDhPrivateKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);

            tempChainKeyHandle.Write(initialChainKey);
            tempDhPrivateKeyHandle.Write(initialDhPrivateKey);

            // Assign only on success
            _chainKeyHandle = tempChainKeyHandle;
            tempChainKeyHandle = null;
            _dhPrivateKeyHandle = tempDhPrivateKeyHandle;
            tempDhPrivateKeyHandle = null;
        }
        catch
        {
            // Dispose temporary handles if assignment failed
            tempChainKeyHandle?.Dispose();
            tempDhPrivateKeyHandle?.Dispose();
            throw; // Re-throw original exception
        }

        _currentIndex = 0;
        _lastUpdate = DateTimeOffset.UtcNow;
        IsNewChain = false; // Initialize flag
        Console.WriteLine(
            $"[{_stepType}] Step Initialized. Index: {_currentIndex}. CK set. DH PK set: {Convert.ToHexString(_dhPublicKey)}");
    }

    internal ShieldMessageKey GetOrDeriveKeyFor(uint targetIndex, SortedDictionary<uint, ShieldMessageKey> messageKeys)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(messageKeys);

        if (messageKeys.TryGetValue(targetIndex, out var cachedKey))
        {
            Console.WriteLine($"[{_stepType}] Found cached key for index {targetIndex}.");
            return cachedKey;
        }

        // Use the CurrentIndex property which reflects the value set by ShieldSession
        uint indexBeforeDerivation = CurrentIndex; // Capture state before loop
        if (targetIndex <= indexBeforeDerivation)
        {
            throw new ShieldChainStepException(
                $"[{_stepType}] Requested index {targetIndex} is not future (current index: {indexBeforeDerivation}) and not found in cache. Cannot re-derive past keys.");
        }

        if (targetIndex > indexBeforeDerivation + 1)
        {
            Console.WriteLine(
                $"[WARN][{_stepType}] Deriving key for future index {targetIndex} from {indexBeforeDerivation + 1}, implying skipped messages.");
        }

        byte[]? currentChainKey = null;
        byte[]? nextChainKey = null;
        byte[]? msgKey = null;


        try
        {
            currentChainKey = new byte[Constants.X25519KeySize];
            nextChainKey = new byte[Constants.X25519KeySize];
            msgKey = new byte[Constants.AesKeySize];

            _chainKeyHandle.Read(currentChainKey.AsSpan());
            Console.WriteLine(
                $"[{_stepType}] Deriving keys from index {indexBeforeDerivation + 1} up to {targetIndex}. Current CK: {Convert.ToHexString(currentChainKey)}");

            // Loop from the *next* expected index up to the target
            for (uint idx = indexBeforeDerivation + 1; idx <= targetIndex; idx++)
            {
                Console.WriteLine($"[{_stepType}] Deriving step for index {idx}");
                using (HkdfSha256 hkdfMsg = new HkdfSha256(currentChainKey, null))
                {
                    hkdfMsg.Expand(Constants.MsgInfo, msgKey.AsSpan());
                }

                using (HkdfSha256 hkdfChain = new HkdfSha256(currentChainKey, null))
                {
                    hkdfChain.Expand(Constants.ChainInfo, nextChainKey.AsSpan());
                }

                // Store derived key in cache
                var messageKey = new ShieldMessageKey(idx, msgKey); // Key gets correct index 'idx'
                if (!messageKeys.TryAdd(idx, messageKey))
                {
                    // Should not happen if cache check worked, but handle defensively
                    messageKey.Dispose();
                    throw new InvalidOperationException(
                        $"Key for index {idx} appeared in cache during derivation loop.");
                }

                Console.WriteLine($"[{_stepType}]   Derived and cached MK {idx}: {Convert.ToHexString(msgKey)}");
                Console.WriteLine($"[{_stepType}]   Derived next CK {idx}: {Convert.ToHexString(nextChainKey)}");

                // Update chain key handle and temp buffer for next iteration
                _chainKeyHandle.Write(nextChainKey);
                Array.Copy(nextChainKey, currentChainKey, nextChainKey.Length);
                // ***** DO NOT UPDATE _currentIndex HERE *****
                // ShieldSession is responsible for updating the index *after* this method returns.
            }

            // _lastUpdate is updated by ShieldSession when it sets CurrentIndex

            // Return the key for the originally requested target index
            return messageKeys[targetIndex];
        }
        finally
        {
            SodiumInterop.SecureWipe(currentChainKey);
            SodiumInterop.SecureWipe(nextChainKey);
            SodiumInterop.SecureWipe(msgKey);
        }
    }

    // Pruning is now called by ShieldSession
    internal void PruneOldKeys(SortedDictionary<uint, ShieldMessageKey> messageKeys)
    {
        ObjectDisposedException.ThrowIf(_disposed, this); // Check if step is disposed
        if (_cacheWindow == 0 || messageKeys == null || !messageKeys.Any()) return;

        uint indexToPruneAgainst = CurrentIndex; // Use the current index set by ShieldSession
        // Calculate the minimum index to keep based on the cache window size
        uint minIndexToKeep = indexToPruneAgainst >= _cacheWindow ? indexToPruneAgainst - _cacheWindow + 1 : 0;

        // Find keys with indices smaller than the minimum to keep
        var keysToRemove = messageKeys.Keys.Where(k => k < minIndexToKeep).ToList();

        if (keysToRemove.Any())
        {
            Console.WriteLine(
                $"[{_stepType}] Pruning keys older than {minIndexToKeep} (CurrentIndex: {indexToPruneAgainst}). Removing count: {keysToRemove.Count}"); // Log count instead of all keys
            foreach (var keyIndex in keysToRemove)
            {
                if (messageKeys.Remove(keyIndex, out var messageKeyToDispose))
                {
                    messageKeyToDispose?.Dispose(); // Dispose the removed key's handle
                }
            }
        }
    }

    // ***** UpdateCurrentIndex METHOD REMOVED *****

    internal void UpdateKeysAfterDhRatchet(byte[] newChainKey, byte[]? newDhPrivateKey = null,
        byte[]? newDhPublicKey = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (newChainKey == null || newChainKey.Length != Constants.X25519KeySize)
            throw new ArgumentException("New chain key invalid.", nameof(newChainKey));

        Console.WriteLine(
            $"[{_stepType}] Updating after DH Ratchet. Old Index: {_currentIndex}. Resetting Index field to 0.");
        _chainKeyHandle.Write(newChainKey);

        // Explicitly reset internal field. ShieldSession will read this via the property getter.
        _currentIndex = 0;

        IsNewChain = true; // Consider if this flag is actually used/needed

        // If new DH keys are provided (only for Sending step usually)
        if (newDhPrivateKey != null && newDhPublicKey != null)
        {
            if (newDhPrivateKey.Length != Constants.X25519PrivateKeySize)
                throw new ArgumentException("Invalid new DH private key.", nameof(newDhPrivateKey));
            if (newDhPublicKey.Length != Constants.X25519KeySize)
                throw new ArgumentException("Invalid new DH public key.", nameof(newDhPublicKey));

            Console.WriteLine($"[{_stepType}] Updating own DH Key Pair.");
            _dhPrivateKeyHandle.Write(newDhPrivateKey); // Update private key handle
            WipeIfNotNull(_dhPublicKey); // Wipe old public key bytes
            _dhPublicKey = (byte[])newDhPublicKey.Clone(); // Store new public key bytes
            Console.WriteLine($"[{_stepType}] New DH Public Key: {Convert.ToHexString(_dhPublicKey)}");
        }
        else if (newDhPrivateKey != null || newDhPublicKey != null)
        {
            // Ensure atomicity - either both or neither
            throw new ArgumentException("Must provide both private and public DH keys, or neither.");
        }

        _lastUpdate = DateTimeOffset.UtcNow; // Update timestamp
    }

    // Reads current chain key into a new byte array
    internal byte[] ReadChainKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] chainKey = new byte[Constants.X25519KeySize];
        _chainKeyHandle.Read(chainKey.AsSpan());
        return chainKey;
    }

    // Reads current DH private key into a new byte array
    internal byte[] ReadDhPrivateKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] privateKey = new byte[Constants.X25519PrivateKeySize];
        _dhPrivateKeyHandle.Read(privateKey.AsSpan());
        return privateKey;
    }

    // Returns a clone of the stored public DH key bytes
    internal byte[] ReadDhPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_dhPublicKey == null) // Should not happen after initialization
            throw new InvalidOperationException("Public DH key data unavailable.");
        return (byte[])_dhPublicKey.Clone();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // Dispose secure handles
        _chainKeyHandle?.Dispose();
        _dhPrivateKeyHandle?.Dispose();

        // Wipe public key bytes (though less critical than private)
        WipeIfNotNull(_dhPublicKey);

        // Nullify references
        _chainKeyHandle = null!;
        _dhPrivateKeyHandle = null!;
        _dhPublicKey = null!;

        GC.SuppressFinalize(this);
    }

    // Helper for secure wiping
    private static void WipeIfNotNull(byte[]? data)
    {
        if (data != null)
            SodiumInterop.SecureWipe(data);
    }
}