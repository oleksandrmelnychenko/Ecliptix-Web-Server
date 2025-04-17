using System.Security.Cryptography;

namespace Ecliptix.Core.Protocol;

/// <summary>
/// Represents a disposable wrapper around a byte array containing sensitive data.
/// Ensures the memory is cleared upon disposal. Thread-safe access.
/// </summary>
public sealed class SecureMemory : IDisposable
{
    private byte[]? _data;
    private readonly Lock _lock = new();
    private bool _disposed;

    public int Length
    {
        get
        {
            lock (_lock)
            {
                return _disposed ? 0 : _data?.Length ?? 0;
            }
        }
    }

    public SecureMemory(ReadOnlySpan<byte> data)
    {
        _data = data.ToArray();
    }

    public SecureMemory(int size)
    {
        if (size < 0) throw new ArgumentOutOfRangeException(nameof(size));
        _data = new byte[size];
    }

    /// <summary>Provides temporary access via a callback. Safer than returning Span directly.</summary>
    public void AccessSecret(Action<ReadOnlySpan<byte>> accessor)
    {
        ArgumentNullException.ThrowIfNull(accessor);
        lock (_lock)
        {
            if (_disposed || _data == null) throw new ObjectDisposedException(nameof(SecureMemory));
            accessor(_data);
        }
    }

    /// <summary>Creates a copy. Manage the returned array's lifetime carefully.</summary>
    public byte[] CopyData()
    {
        lock (_lock)
        {
            return _disposed || _data == null
                ? throw new ObjectDisposedException(nameof(SecureMemory))
                : (byte[])_data.Clone();
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        lock (_lock)
        {
            if (!_disposed)
            {
                if (_data != null)
                {
                    CryptographicOperations.ZeroMemory(_data);
                    _data = null;
                }

                _disposed = true;
            }
        }
    }

    ~SecureMemory()
    {
        Dispose(false);
    }

    public ReadOnlySpan<byte> ExposeSecret()
    {
        lock (_lock)
        {
            // Check disposal state first
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(SecureMemory));
            }

            // _data should not be null if not disposed, but check defensively
            if (_data == null)
            {
                // This indicates an inconsistent state, should ideally not happen if not disposed
                throw new InvalidOperationException(
                    "SecureMemory is in an invalid state (data is null but not disposed).");
            }

            // Return the underlying array as a ReadOnlySpan
            return _data;
        }
    }
}