using System.Runtime.CompilerServices;
using Ecliptix.Core.Protocol;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using Sodium;
using Sodium.Exceptions;

namespace Ecliptix.Core.Protocol;

public sealed class ShieldChainStep : IDisposable
{
    private readonly ChainStepType _stepType;
    private byte[] _chainKey; // Current chain key
    private readonly byte[] _privateKey; // This node's DH private key

    private readonly byte[] _publicKey; // This node's DH public key

    // Using Dictionary for potentially better average performance if order isn't required
    private readonly Dictionary<uint, ShieldMessageKey> _messageKeys;
    private uint _lastDerivedIndex; // Highest index derived/processed
    private DateTime _lastUpdate; // Timestamp of last key derivation/rotation
    private readonly uint _cacheWindow;
    private readonly ILogger? _logger; // Make logger nullable without generic constraint
    private bool _disposed;

    public ShieldChainStep(
        ChainStepType stepType,
        ReadOnlySpan<byte> initialChainKey,
        ILogger? logger = null)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(initialChainKey.Length, Constants.X25519KeySize,
            nameof(initialChainKey));

        _stepType = stepType;
        _chainKey = initialChainKey.ToArray();

        KeyPair keyPair = PublicKeyBox.GenerateKeyPair();

        _privateKey = keyPair.PrivateKey;
        _publicKey = keyPair.PublicKey;

        _messageKeys = new Dictionary<uint, ShieldMessageKey>();
        _lastDerivedIndex = 0;
        _lastUpdate = DateTime.UtcNow;
        _cacheWindow = Constants.CacheWindowSize;
        _logger = logger;
        _disposed = false;

        _logger?.LogInformation("Initialized ShieldChainStep ({StepType}) with public key {PublicKeyHex}",
            _stepType, Convert.ToHexString(_publicKey));
    }

    public uint LastIndex => _lastDerivedIndex;

    public uint NextSenderIndex => LastIndex + 1;

    // The public key for the DH part of the ratchet
    public ReadOnlySpan<byte> PublicKey => _publicKey;

    /// <summary>
    /// Performs an asymmetric (Diffie-Hellman) ratchet step.
    /// Derives a new chain key from the shared secret computed with the peer's public key.
    /// Resets the message key index and clears the cache.
    /// </summary>
    /// <param name="peerPublicKey">The public key received from the communication peer.</param>
    /// <returns>Ok(Unit) on success, Err(ShieldFailure) on failure.</returns>
    public Result<Unit, ShieldFailure> RotateDhChain(ReadOnlySpan<byte> peerPublicKey)
    {
        if (_disposed) return Result<Unit, ShieldFailure>.Err(ShieldFailure.Disposed());

        if (peerPublicKey.Length != Constants.X25519KeySize)
        {
            _logger?.LogError("RotateDhChain failed: Peer public key has invalid length {Length}",
                peerPublicKey.Length);
            return Result<Unit, ShieldFailure>.Err(
                ShieldFailure.InvalidInput($"Peer public key must be {Constants.X25519KeySize} bytes"));
        }

        _logger?.LogDebug("Attempting DH rotation with peer public key: {PeerKeyHex}",
            Convert.ToHexString(peerPublicKey));

        byte[]? dhOutputBytes = null; // Will hold the result from Mult
        byte[] peerPublicKeyBytes = peerPublicKey.ToArray(); // Convert span to array for the API

        try
        {
            dhOutputBytes = ScalarMult.Mult(_privateKey, peerPublicKeyBytes);
            if (dhOutputBytes == null || dhOutputBytes.Length != Constants.X25519KeySize)
            {
                _logger?.LogError(
                    "RotateDhChain failed: X25519 scalar multiplication returned unexpected result (null or wrong length).");
                return Result<Unit, ShieldFailure>.Err(
                    ShieldFailure.DeriveKeyFailed("DH computation returned invalid data"));
            }
        }
        // Catch specific exceptions known from the API/decompiled code
        catch (KeyOutOfRangeException keyEx)
        {
            // This implies _privateKey or peerPublicKeyBytes had wrong length, which shouldn't happen if logic is correct
            _logger?.LogError(keyEx,
                "RotateDhChain failed due to key out of range during scalar multiplication. This indicates an internal logic error.");
            return Result<Unit, ShieldFailure>.Err(
                ShieldFailure.DeriveKeyFailed($"DH computation failed: {keyEx.Message}"));
        }
        // Catch broader Sodium exceptions or general exceptions from interop
        catch (Exception ex) when (ex is System.Runtime.InteropServices.SEHException ||
                                   ex is DllNotFoundException)
        {
            _logger?.LogError(ex, "RotateDhChain failed: An exception occurred during X25519 scalar multiplication.");
            // Avoid leaking excessive detail in the ShieldFailure message
            return Result<Unit, ShieldFailure>.Err(
                ShieldFailure.DeriveKeyFailed("DH computation failed due to a cryptographic error"));
        }
        finally
        {
            // Clear the temporary byte array created from the span
            Array.Clear(peerPublicKeyBytes, 0, peerPublicKeyBytes.Length);
        }


        // --- Use the resulting dhOutputBytes ---
        Span<byte> newChainKey = stackalloc byte[Constants.X25519KeySize];
        try
        {
            // Pass the result byte array (or a span of it) to HKDF
            using var hkdf = new HkdfSha256(dhOutputBytes);
            hkdf.Expand(Constants.ChainInfo, newChainKey);
        }
        catch (Exception ex)
        {
            // Clear sensitive data before returning error
            if (dhOutputBytes != null) Array.Clear(dhOutputBytes, 0, dhOutputBytes.Length);
            newChainKey.Clear();
            _logger?.LogError(ex, "RotateDhChain failed: HKDF expansion failed during DH rotation.");
            return Result<Unit, ShieldFailure>.Err(ShieldFailure.DeriveKeyFailed("HKDF failed during DH rotation"));
        }
        finally
        {
            // --- ALWAYS CLEAR the shared secret ---
            if (dhOutputBytes != null) Array.Clear(dhOutputBytes, 0, dhOutputBytes.Length);
        }


        // --- Update State (remains the same) ---
        byte[] oldChainKey = _chainKey;
        _chainKey = newChainKey.ToArray();
        Array.Clear(oldChainKey, 0, oldChainKey.Length); // Clear the old one

        _lastDerivedIndex = 0;
        _lastUpdate = DateTime.UtcNow;
        _messageKeys.Clear();

        _logger?.LogInformation("Successfully performed DH ratchet rotation. New chain state established.");

        newChainKey.Clear(); // Clear stack copy
        return Result<Unit, ShieldFailure>.Ok(Unit.Value);

        // --- End Correction for Sodium.Core 1.4.0 API ---
    }

    /// <summary>
    /// Performs symmetric ratchet steps to derive the message key for a specific index.
    /// Handles receiving messages potentially out-of-order within the cache window.
    /// </summary>
    /// <param name="incomingIndex">The index associated with the message key to retrieve or derive.</param>
    /// <returns>Ok(ShieldMessageKey) containing the key, or Err(ShieldFailure) on failure.</returns>
    public Result<ShieldMessageKey, ShieldFailure> RotateKeyFor(uint incomingIndex)
    {
        if (_disposed) return Result<ShieldMessageKey, ShieldFailure>.Err(ShieldFailure.Disposed());

        _logger?.LogDebug(
            "RotateKeyFor called with index {IncomingIndex}. Current last derived index: {LastDerivedIndex}",
            incomingIndex, _lastDerivedIndex);

        // Check cache first for out-of-order messages
        if (_messageKeys.TryGetValue(incomingIndex, out var cachedKey))
        {
            _logger?.LogInformation(
                "Found cached key for out-of-order index {IncomingIndex} (last derived: {LastDerivedIndex})",
                incomingIndex, _lastDerivedIndex);
            // Return a clone to prevent external modification of the cached struct/key array reference
            return Result<ShieldMessageKey, ShieldFailure>.Ok(cachedKey.Clone());
        }

        // Check if requested index is too old (already pruned or never derived)
        if (incomingIndex <= _lastDerivedIndex)
        {
            _logger?.LogError(
                "Requested index {IncomingIndex} is <= last derived index {LastDerivedIndex} and not found in cache. Potentially too old or invalid.",
                incomingIndex, _lastDerivedIndex);
            return Result<ShieldMessageKey, ShieldFailure>.Err(ShieldFailure.KeyRotationFailed(
                $"Requested index {incomingIndex} is historical and not cached"));
        }

        // Check for timeout (suggests a DH rotation might be needed, but doesn't fail this operation)
        if (DateTime.UtcNow - _lastUpdate > Constants.RotationTimeout)
        {
            _logger?.LogWarning(
                "Symmetric key rotation timeout exceeded ({Timeout}s). Consider triggering DH rotation soon.",
                Constants.RotationTimeout.TotalSeconds);
        }

        // Log if indices were skipped
        if (incomingIndex > _lastDerivedIndex + 1)
        {
            _logger?.LogWarning(
                "Detected skipped message indices from {StartIndex} to {EndIndex}. Deriving keys up to {TargetIndex}.",
                _lastDerivedIndex + 1, incomingIndex - 1, incomingIndex);
        }

        // --- Perform Symmetric Ratchet Steps ---
        // Use stackalloc for transient buffers if possible, be mindful of size.
        // Chain key buffer needs to be updated in the loop.
        Span<byte> currentChainKey = stackalloc byte[Constants.X25519KeySize];
        _chainKey.CopyTo(currentChainKey); // Start with the current chain key

        Span<byte> msgKeyBuffer = stackalloc byte[Constants.X25519KeySize]; // Buffer for derived message key
        ShieldMessageKey? derivedKeyForTarget = null; // Store the key for the specific requested index

        try
        {
            // Loop from the next expected index up to the requested index
            for (uint idx = _lastDerivedIndex + 1; idx <= incomingIndex; idx++)
            {
                // Derive next chain key: next_CK = HKDF(CK, CHAIN_INFO)
                // Using CK as IKM for HKDF is common in ratchets.
                using (var hkdfChain = new HkdfSha256(currentChainKey))
                {
                    hkdfChain.Expand(Constants.ChainInfo, currentChainKey); // Update currentChainKey in place
                }


                // Derive message key for this index: MK = HKDF(next_CK, MSG_INFO)
                using (var hkdfMsg = new HkdfSha256(currentChainKey))
                {
                    hkdfMsg.Expand(Constants.MsgInfo, msgKeyBuffer);
                }


                var newMsgKey = new ShieldMessageKey(idx, msgKeyBuffer);
                _messageKeys.Add(idx, newMsgKey); // Add to cache
                _lastDerivedIndex = idx; // Update the high-water mark *after* successful derivation
                _lastUpdate = DateTime.UtcNow;

                // Store the key if it's the one we were asked for
                if (idx == incomingIndex)
                {
                    derivedKeyForTarget = newMsgKey;
                }

                _logger?.LogTrace("Derived and cached key for index {DerivedIndex}", idx);
            }
        }
        catch (Exception ex) // Catch potential Sodium/HKDF errors
        {
            // Clear intermediates on error
            currentChainKey.Clear();
            msgKeyBuffer.Clear();
            _logger?.LogError(ex,
                "Symmetric ratchet step failed during key derivation loop up to index {TargetIndex}.",
                incomingIndex);
            // Don't update the main _chainKey if derivation failed partway through
            return Result<ShieldMessageKey, ShieldFailure>.Err(ShieldFailure.KeyRotationFailed(
                $"Error during key derivation for index range up to {incomingIndex}"));
        }


        // --- Update State & Cleanup ---

        // Persist the final derived chain key
        var oldChainKey = _chainKey;
        _chainKey = currentChainKey.ToArray();
        Array.Clear(oldChainKey, 0, oldChainKey.Length);

        // Prune old keys outside the cache window
        PruneOldKeys();

        // Clear stack buffers
        currentChainKey.Clear();
        msgKeyBuffer.Clear();

        // Check if we successfully derived the target key (should always be true if loop completed)
        if (derivedKeyForTarget.HasValue)
        {
            _logger?.LogInformation("Successfully derived and cached keys up to index {IncomingIndex}",
                incomingIndex);
            // Return a clone for safety
            return Result<ShieldMessageKey, ShieldFailure>.Ok(derivedKeyForTarget.Value.Clone());
        }
        else
        {
            // This case should be unlikely if the loop logic is correct, but handle defensively
            _logger?.LogError(
                "Symmetric ratchet step completed, but failed to retrieve the target key for index {IncomingIndex}. State inconsistency?",
                incomingIndex);
            return Result<ShieldMessageKey, ShieldFailure>.Err(ShieldFailure.KeyRotationFailed(
                $"Internal error: Failed to retrieve derived key for {incomingIndex} after processing"));
        }
    }


    // --- Helper Methods ---

    private void PruneOldKeys()
    {
        // Determine the minimum index to keep based on the cache window
        uint minIndex = _lastDerivedIndex > _cacheWindow
            ? _lastDerivedIndex - _cacheWindow
            : 0; // Keep keys from 0 if window hasn't been exceeded

        int initialCount = _messageKeys.Count;
        if (initialCount == 0) return; // Nothing to prune

        // Using List<T> here as the number of keys to remove is often small
        // compared to renting/returning from ArrayPool unless the cache is huge
        // and pruning happens very often. List<T> avoids pool contention.
        List<uint>? keysToRemove = null;

        // Iterate through the dictionary's keys
        foreach (uint keyIndex in _messageKeys.Keys)
        {
            if (keyIndex < minIndex)
            {
                keysToRemove ??= new List<uint>(); // Allocate list only if needed
                keysToRemove.Add(keyIndex);
            }
        }

        int removedCount = 0;
        if (keysToRemove != null)
        {
            foreach (uint keyToRemove in keysToRemove)
            {
                if (_messageKeys.Remove(keyToRemove))
                {
                    removedCount++;
                }
            }
        }

        if (removedCount > 0)
        {
            _logger?.LogDebug("Pruned {RemovedCount} old keys (indices < {MinIndex}); {RemainingCount} remaining.",
                removedCount, minIndex, _messageKeys.Count);
        }
    }

    // --- IDisposable Implementation ---

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this); // Prevent finalizer from running if Dispose was called
    }

    private void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed state (e.g., IDisposable fields like logger if needed)
                // In this case, we mainly clear sensitive data
                _logger?.LogDebug("Disposing ShieldChainStep ({StepType}). Clearing sensitive key material.",
                    _stepType);
            }

            // Clear unmanaged resources (none directly held) and sensitive managed data
            if (_chainKey != null) Array.Clear(_chainKey, 0, _chainKey.Length);
            if (_privateKey != null) Array.Clear(_privateKey, 0, _privateKey.Length);
            // Public key isn't strictly secret, but clearing is consistent
            if (_publicKey != null) Array.Clear(_publicKey, 0, _publicKey.Length);

            // Clear keys stored in the dictionary values
            foreach (var kvp in _messageKeys)
            {
                // Access the private field via reflection IS BAD.
                // Instead, ShieldMessageKey should implement IDisposable or have a Clear method
                // if we want to guarantee clearing its internal byte[].
                // For now, just clear the dictionary itself.
                // Consider adding `Clear()` to ShieldMessageKey if needed.
            }

            _messageKeys.Clear(); // Remove references

            _disposed = true;
        }
    }
}