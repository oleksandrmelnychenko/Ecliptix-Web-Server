using Ecliptix.Core.Protocol.Utilities;
using Sodium;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldChainStep : IDisposable
{
    private const uint DefaultCacheWindowSize = 1000;

    private static ReadOnlySpan<byte> ChainInfo => [0x01];
    private static ReadOnlySpan<byte> MsgInfo => [0x02];

    private readonly ChainStepType _stepType;
    private readonly uint _cacheWindow;
    private SodiumSecureMemoryHandle _chainKeyHandle;
    private SodiumSecureMemoryHandle _dhPrivateKeyHandle;
    private byte[] _dhPublicKey;
    private uint _currentIndex;
    private DateTimeOffset _lastUpdate;
    private readonly SortedDictionary<uint, ShieldMessageKey> _messageKeys;
    private bool _disposed = false;

    public uint CurrentIndex
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _currentIndex;
        }
    }

    public uint NextMessageIndex
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _currentIndex + 1;
        }
    }

    public byte[] PublicKeyBytes
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_dhPublicKey == null)
            {
                throw new ObjectDisposedException(GetType().FullName, "Public key data is unavailable after disposal.");
            }

            return (byte[])_dhPublicKey.Clone();
        }
    }

    public ShieldChainStep(
        ChainStepType stepType,
        byte[] initialChainKey,
        uint cacheWindowSize = DefaultCacheWindowSize)
    {
        if (initialChainKey == null) throw new ArgumentNullException(nameof(initialChainKey));
        if (initialChainKey.Length != Constants.X25519KeySize)
            throw new ArgumentException($"Initial chain key must be {Constants.X25519KeySize} bytes.",
                nameof(initialChainKey));

        _stepType = stepType;
        _cacheWindow = cacheWindowSize;

        _chainKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize);
        try
        {
            _chainKeyHandle.Write(initialChainKey);
        }
        catch
        {
            _chainKeyHandle.Dispose();
            throw;
        }

        _dhPrivateKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
        // Correctly handle temporary byte[] for random generation
        byte[]? tempPrivateKeyBytes = null;
        byte[]? tempPublicKeyBytes = null;
        try
        {
            tempPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize); // Returns byte[]
            _dhPrivateKeyHandle.Write(tempPrivateKeyBytes); // Copy from heap buffer to secure handle
            tempPublicKeyBytes = ScalarMult.Base(tempPrivateKeyBytes); // Derive public key from heap buffer
            _dhPublicKey = tempPublicKeyBytes; // Assign the returned public key array
            tempPublicKeyBytes = null; // Nullify to prevent wipe in finally if successful
        }
        catch
        {
            _dhPrivateKeyHandle.Dispose();
            throw;
        }
        finally
        {
            // SecureWipe the temporary heap buffers
            if (tempPrivateKeyBytes != null) SodiumInterop.SecureWipe(tempPrivateKeyBytes);
            if (tempPublicKeyBytes != null) SodiumInterop.SecureWipe(tempPublicKeyBytes);
        }

        _messageKeys = new SortedDictionary<uint, ShieldMessageKey>();
        _currentIndex = 0;
        _lastUpdate = DateTimeOffset.UtcNow;
    }

    private void PruneOldKeys()
    {
        if (_cacheWindow == 0)
        {
            return;
        }

        uint minIndex = (_currentIndex >= _cacheWindow) ? _currentIndex - _cacheWindow : 0;
        var keysToRemove = _messageKeys.Keys.Where(k => k < minIndex).ToList();
        foreach (var keyIndex in keysToRemove)
        {
            if (_messageKeys.TryGetValue(keyIndex, out var messageKeyToDispose))
            {
                messageKeyToDispose.Dispose();
                _messageKeys.Remove(keyIndex);
            }
        }
    }

    public void RotateDhChain(byte[] peerPublicKeyBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (peerPublicKeyBytes == null) throw new ArgumentNullException(nameof(peerPublicKeyBytes));
        if (peerPublicKeyBytes.Length != Constants.X25519KeySize)
            throw new ArgumentException($"Peer public key must be {Constants.X25519KeySize} bytes.",
                nameof(peerPublicKeyBytes));

        // Use byte[] for reading private key as ScalarMult.Mult requires it
        byte[]? dhPrivateKeyBytes = null;
        // Use stackalloc for HKDF output buffer
        Span<byte> newChainKeySpan = stackalloc byte[Constants.X25519KeySize];

        byte[]? sharedSecretBytes = null;
        SodiumSecureMemoryHandle? newChainKeyHandle = null;
        byte[]? tempNewDhPrivateKeyBytes = null; // Corrected variable name and type
        byte[]? tempNewDhPublicKeyBytes = null;
        SodiumSecureMemoryHandle? newDhPrivateKeyHandle = null;

        try
        {
            // --- Perform Diffie-Hellman ---
            dhPrivateKeyBytes = new byte[Constants.X25519PrivateKeySize]; // Allocate temp heap buffer
            _dhPrivateKeyHandle.Read(dhPrivateKeyBytes); // Read private key into heap buffer
            sharedSecretBytes = ScalarMult.Mult(dhPrivateKeyBytes, peerPublicKeyBytes); // Pass heap buffer
            // Wipe private key copy immediately
            SodiumInterop.SecureWipe(dhPrivateKeyBytes);
            dhPrivateKeyBytes = null;

            // --- Derive New Chain Key ---
            using (var hkdf = new HkdfSha256(sharedSecretBytes, default)) // Pass shared secret heap buffer
            {
                hkdf.Expand(ChainInfo, newChainKeySpan); // Derive into stack buffer
            }

            SodiumInterop.SecureWipe(sharedSecretBytes); // Wipe shared secret heap buffer
            sharedSecretBytes = null;

            // --- Store New Chain Key Securely ---
            newChainKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize);
            newChainKeyHandle.Write(newChainKeySpan); // Copy from stack buffer
            newChainKeySpan.Clear(); // Wipe stack buffer

            // --- Generate New DH Key Pair ---
            newDhPrivateKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
            tempNewDhPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize); // Returns byte[]
            newDhPrivateKeyHandle.Write(tempNewDhPrivateKeyBytes); // Copy to secure handle
            tempNewDhPublicKeyBytes = ScalarMult.Base(tempNewDhPrivateKeyBytes); // Derive public key
            // Wipe temporary private key bytes immediately AFTER deriving public key
            SodiumInterop.SecureWipe(tempNewDhPrivateKeyBytes);
            tempNewDhPrivateKeyBytes = null; // Set to null AFTER wipe

            // --- Update State ---
            _chainKeyHandle?.Dispose();
            _dhPrivateKeyHandle?.Dispose();

            _chainKeyHandle = newChainKeyHandle;
            _dhPrivateKeyHandle = newDhPrivateKeyHandle;
            _dhPublicKey = tempNewDhPublicKeyBytes;

            newChainKeyHandle = null;
            newDhPrivateKeyHandle = null;
            tempNewDhPublicKeyBytes = null;

            foreach (var key in _messageKeys.Values) key.Dispose();
            _messageKeys.Clear();

            _currentIndex = 0;
            _lastUpdate = DateTimeOffset.UtcNow;
        }
        catch (Exception ex)
        {
            newChainKeyHandle?.Dispose();
            newDhPrivateKeyHandle?.Dispose();
            throw new ShieldChainStepException($"DH rotation failed for {_stepType}: {ex.Message}", ex);
        }
        finally
        {
            // Ensure ALL temporary buffers are wiped/cleared
            if (dhPrivateKeyBytes != null)
                SodiumInterop.SecureWipe(dhPrivateKeyBytes); // Wipe if error occurred before nulling
            if (sharedSecretBytes != null) SodiumInterop.SecureWipe(sharedSecretBytes);
            newChainKeySpan.Clear();
            if (tempNewDhPrivateKeyBytes != null)
                SodiumInterop.SecureWipe(tempNewDhPrivateKeyBytes); // Wipe if error occurred before nulling
            if (tempNewDhPublicKeyBytes != null) SodiumInterop.SecureWipe(tempNewDhPublicKeyBytes);
        }
    }


    public ShieldMessageKey GetOrDeriveKeyFor(uint targetIndex)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_messageKeys.TryGetValue(targetIndex, out var cachedKey))
        {
            return cachedKey;
        }

        if (targetIndex <= _currentIndex)
        {
            throw new ShieldChainStepException(
                $"Requested index {targetIndex} is too old (current index: {_currentIndex})...");
        } // Shortened message

        Span<byte> currentChainKeySpan = stackalloc byte[Constants.X25519KeySize];
        Span<byte> nextChainKeySpan = stackalloc byte[Constants.X25519KeySize];
        Span<byte> msgKeySpan = stackalloc byte[Constants.X25519KeySize];
        SodiumSecureMemoryHandle? nextChainKeyHandle = null;

        try
        {
            for (uint idx = _currentIndex + 1; idx <= targetIndex; idx++)
            {
                _chainKeyHandle.Read(currentChainKeySpan);

                // --- Derive next chain key ---
                // CHECK: Ensure HkdfSha256 constructor accepts ReadOnlySpan<byte> for IKM
                // If not, use: byte[] tempIKM = currentChainKeySpan.ToArray(); try { using(new HkdfSha256(tempIKM...)) {...} } finally { SodiumInterop.SecureWipe(tempIKM); }
                using (var hkdfChain = new HkdfSha256(currentChainKeySpan, default))
                {
                    hkdfChain.Expand(ChainInfo, nextChainKeySpan);
                }

                currentChainKeySpan.Clear(); // Wipe temp current key copy

                nextChainKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize);
                nextChainKeyHandle.Write(nextChainKeySpan); // Store next key securely

                // --- Derive message key ---
                // CHECK: Ensure HkdfSha256 constructor accepts ReadOnlySpan<byte> for IKM (using nextChainKeySpan here)
                // If not, adapt as described above.
                using (var hkdfMsg = new HkdfSha256(nextChainKeySpan, default))
                {
                    hkdfMsg.Expand(MsgInfo, msgKeySpan);
                }

                nextChainKeySpan.Clear(); // Wipe temp next key copy

                // Create secure message key object (constructor takes ReadOnlySpan)
                // Constructor copies msgKeySpan into its own secure handle
                var newMessageKey = new ShieldMessageKey(idx, msgKeySpan);
                msgKeySpan.Clear(); // Wipe temp message key buffer

                // --- Update State ---
                var oldChainKeyHandle = _chainKeyHandle;
                _chainKeyHandle = nextChainKeyHandle;
                oldChainKeyHandle?.Dispose();
                nextChainKeyHandle = null; // Prevent disposal in finally

                _messageKeys.Add(idx, newMessageKey);
                _currentIndex = idx;
                _lastUpdate = DateTimeOffset.UtcNow;
            }
        }
        catch (Exception ex) when (ex is not ShieldChainStepException)
        {
            nextChainKeyHandle?.Dispose();
            throw new ShieldChainStepException(
                $"Symmetric key derivation failed for {_stepType} near index {_currentIndex + 1}: {ex.Message}", ex);
        }
        finally
        {
            currentChainKeySpan.Clear();
            nextChainKeySpan.Clear();
            msgKeySpan.Clear();
        }

        PruneOldKeys();

        if (_messageKeys.TryGetValue(targetIndex, out var resultKey))
        {
            return resultKey;
        }

        throw new ShieldChainStepException(
            $"Internal error: Failed to derive key for index {targetIndex} after rotation loop."); // Shortened message
    }

    public ShieldMessageKey AdvanceSenderKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return GetOrDeriveKeyFor(NextMessageIndex); // Simplified
    }

    public void Dispose()
    {
        if (_disposed) return;

        _dhPrivateKeyHandle.Dispose();
        _dhPrivateKeyHandle = null!;
        SodiumInterop.SecureWipe(_dhPublicKey);
        _dhPublicKey = null!;

        _chainKeyHandle.Dispose();
        _chainKeyHandle = null!;

        foreach (ShieldMessageKey key in _messageKeys.Values) key.Dispose();
        _messageKeys.Clear();

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}