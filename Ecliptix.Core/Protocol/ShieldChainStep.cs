using Ecliptix.Core.Protocol.Utilities;
using Sodium;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldChainStep : IDisposable
{
    private const uint DefaultCacheWindowSize = 1000;
    private const uint DhRotationInterval = 1000;

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
                throw new ObjectDisposedException(GetType().FullName, "Public key data is unavailable after disposal.");
            return (byte[])_dhPublicKey.Clone();
        }
    }

    internal bool HasDerivedKeys
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _currentIndex > 0;
        }
    }

    public ShieldChainStep(ChainStepType stepType, byte[] initialChainKey,
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
        byte[]? tempPrivateKeyBytes = null;
        byte[]? tempPublicKeyBytes = null;
        try
        {
            tempPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            _dhPrivateKeyHandle.Write(tempPrivateKeyBytes);
            tempPublicKeyBytes = ScalarMult.Base(tempPrivateKeyBytes);
            _dhPublicKey = tempPublicKeyBytes;
            tempPublicKeyBytes = null;
        }
        catch
        {
            _dhPrivateKeyHandle.Dispose();
            throw;
        }
        finally
        {
            if (tempPrivateKeyBytes != null) SodiumInterop.SecureWipe(tempPrivateKeyBytes);
            if (tempPublicKeyBytes != null) SodiumInterop.SecureWipe(tempPublicKeyBytes);
        }

        _messageKeys = new SortedDictionary<uint, ShieldMessageKey>();
        _currentIndex = 0;
        _lastUpdate = DateTimeOffset.UtcNow;
    }

    private void PruneOldKeys()
    {
        if (_cacheWindow == 0) return;

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

        byte[]? dhPrivateKeyBytes = null;
        Span<byte> newChainKeySpan = stackalloc byte[Constants.X25519KeySize];
        byte[]? sharedSecretBytes = null;
        SodiumSecureMemoryHandle? newChainKeyHandle = null;
        byte[]? tempNewDhPrivateKeyBytes = null;
        byte[]? tempNewDhPublicKeyBytes = null;
        SodiumSecureMemoryHandle? newDhPrivateKeyHandle = null;

        try
        {
            dhPrivateKeyBytes = new byte[Constants.X25519PrivateKeySize];
            _dhPrivateKeyHandle.Read(dhPrivateKeyBytes);
            sharedSecretBytes = ScalarMult.Mult(dhPrivateKeyBytes, peerPublicKeyBytes);
            SodiumInterop.SecureWipe(dhPrivateKeyBytes);
            dhPrivateKeyBytes = null;

            using (var hkdf = new HkdfSha256(sharedSecretBytes, default))
            {
                hkdf.Expand(Constants.ChainInfo, newChainKeySpan);
            }

            SodiumInterop.SecureWipe(sharedSecretBytes);
            sharedSecretBytes = null;

            newChainKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize);
            newChainKeyHandle.Write(newChainKeySpan);
            newChainKeySpan.Clear();

            newDhPrivateKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
            tempNewDhPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            newDhPrivateKeyHandle.Write(tempNewDhPrivateKeyBytes);
            tempNewDhPublicKeyBytes = ScalarMult.Base(tempNewDhPrivateKeyBytes);
            SodiumInterop.SecureWipe(tempNewDhPrivateKeyBytes);
            tempNewDhPrivateKeyBytes = null;

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
            if (dhPrivateKeyBytes != null) SodiumInterop.SecureWipe(dhPrivateKeyBytes);
            if (sharedSecretBytes != null) SodiumInterop.SecureWipe(sharedSecretBytes);
            newChainKeySpan.Clear();
            if (tempNewDhPrivateKeyBytes != null) SodiumInterop.SecureWipe(tempNewDhPrivateKeyBytes);
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
        }

        Span<byte> currentChainKeySpan = stackalloc byte[Constants.X25519KeySize];
        Span<byte> nextChainKeySpan = stackalloc byte[Constants.X25519KeySize];
        Span<byte> msgKeySpan = stackalloc byte[Constants.X25519KeySize];
        SodiumSecureMemoryHandle? nextChainKeyHandle = null;

        try
        {
            for (uint idx = _currentIndex + 1; idx <= targetIndex; idx++)
            {
                _chainKeyHandle.Read(currentChainKeySpan);

                using (HkdfSha256 hkdfChain = new(currentChainKeySpan, default))
                {
                    hkdfChain.Expand(Constants.ChainInfo, nextChainKeySpan);
                }

                currentChainKeySpan.Clear();

                nextChainKeyHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize);
                nextChainKeyHandle.Write(nextChainKeySpan);

                using (HkdfSha256 hkdfMsg = new(nextChainKeySpan, default))
                {
                    hkdfMsg.Expand(Constants.MsgInfo, msgKeySpan);
                }

                nextChainKeySpan.Clear();

                Console.WriteLine("[GetOrDeriveKeyFor] Deriving message key for index: " + idx);
                Console.WriteLine("Key: " + Convert.ToHexString(msgKeySpan.ToArray()));

                ShieldMessageKey newMessageKey = new(idx, msgKeySpan);
                msgKeySpan.Clear();

                var oldChainKeyHandle = _chainKeyHandle;
                _chainKeyHandle = nextChainKeyHandle;
                oldChainKeyHandle?.Dispose();
                nextChainKeyHandle = null;

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
            $"Internal error: Failed to derive key for index {targetIndex} after rotation loop.");
    }

    public (ShieldMessageKey MessageKey, byte[]? NewDhPublicKey) AdvanceSenderKey(byte[] peerPublicKeyBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (peerPublicKeyBytes == null) throw new ArgumentNullException(nameof(peerPublicKeyBytes));
        if (peerPublicKeyBytes.Length != Constants.X25519KeySize)
            throw new ArgumentException($"Peer public key must be {Constants.X25519KeySize} bytes.",
                nameof(peerPublicKeyBytes));

        byte[]? newDhPublicKey = null;
        if (NextMessageIndex % DhRotationInterval == 0 && HasDerivedKeys)
        {
            RotateDhChain(peerPublicKeyBytes);
            newDhPublicKey = PublicKeyBytes;
        }

        ShieldMessageKey messageKey = GetOrDeriveKeyFor(NextMessageIndex);
        return (messageKey, newDhPublicKey);
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