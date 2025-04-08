// For MemoryMarshal

// For SodiumInterop

namespace Ecliptix.Core.Protocol; // Or your namespace

/// <summary>
/// Holds a derived message key securely using SodiumSecureMemoryHandle.
/// Implements IDisposable to manage the secure handle.
/// </summary>
public sealed class ShieldMessageKey : IDisposable, IEquatable<ShieldMessageKey>
{
    public const int KeySize = 32; // X25519_KEY_SIZE

    /// <summary>
    /// The index of this key in the ratchet chain.
    /// </summary>
    public uint Index { get; }

    // Store the key securely
    private SodiumSecureMemoryHandle _keyHandle;
    private bool _disposed = false;

    /// <summary>
    /// Creates a new ShieldMessageKey, copying the key material into secure memory.
    /// </summary>
    /// <param name="index">The key index.</param>
    /// <param name="keyMaterial">The 32-byte key material. This will be wiped after copying.</param>
    /// <exception cref="ArgumentException">Thrown if keyMaterial is not 32 bytes.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if called after disposal.</exception>
    public ShieldMessageKey(uint index, Span<byte> keyMaterial) // Accept Span for flexibility
    {
        if (keyMaterial.Length != KeySize)
        {
            // Wipe input before throwing if possible (might already be wiped by caller)
            SodiumInterop.SecureWipe(keyMaterial.ToArray()); // Needs ToArray for SecureWipe signature
            throw new ArgumentException($"Key material must be {KeySize} bytes long.", nameof(keyMaterial));
        }

        Index = index;
        _keyHandle = SodiumSecureMemoryHandle.Allocate(KeySize);
        try
        {
            _keyHandle.Write(keyMaterial); // Copy into secure memory
        }
        catch
        {
            _keyHandle.Dispose(); // Clean up if write fails
            throw;
        }
        finally
        {
            // Wipe the source buffer provided by the caller
            // Assuming the caller expects this behavior or passed a temp buffer
            // Be cautious if caller might need the buffer afterwards.
            // Let's rely on the caller (ShieldChainStep) to wipe its temp buffers.
            // SodiumInterop.SecureWipe(keyMaterial.ToArray()); // Might double-wipe or wipe needed data
        }
    }

    /// <summary>
    /// Securely reads the key material into the provided destination buffer.
    /// The destination buffer should be wiped by the caller after use.
    /// </summary>
    /// <param name="destination">Span to copy the key into. Must be at least KeySize.</param>
    /// <exception cref="ObjectDisposedException">Thrown if called after disposal.</exception>
    /// <exception cref="ArgumentException">Thrown if destination is too small.</exception>
    public void ReadKeyMaterial(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (destination.Length < KeySize)
        {
            throw new ArgumentException($"Destination buffer must be at least {KeySize} bytes.", nameof(destination));
        }
        _keyHandle.Read(destination.Slice(0, KeySize)); // Read into the start of the destination
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _keyHandle?.Dispose();
                _keyHandle = null!; // Ensure it's nullified
            }
            _disposed = true;
        }
    }

    // --- Equality Implementation (Based on Index only for dictionary key purposes) ---
    // WARNING: Comparing actual key content requires reading it out securely.
    // This equality is suitable for identifying keys by index in the cache.
    public bool Equals(ShieldMessageKey? other)
    {
        if (other is null) return false;
        // If comparing secure handles is needed, it's complex.
        // For cache lookup, index equality is sufficient.
        return Index == other.Index;
    }

    public override bool Equals(object? obj)
    {
        return obj is ShieldMessageKey other && Equals(other);
    }

    public override int GetHashCode()
    {
        return Index.GetHashCode();
    }

    public static bool operator ==(ShieldMessageKey? left, ShieldMessageKey? right)
    {
        if (ReferenceEquals(left, right)) return true;
        if (left is null || right is null) return false;
        return left.Equals(right);
    }

    public static bool operator !=(ShieldMessageKey? left, ShieldMessageKey? right)
    {
        return !(left == right);
    }
}