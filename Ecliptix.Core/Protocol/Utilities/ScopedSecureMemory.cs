using System.Security.Cryptography;

namespace Ecliptix.Core.Protocol.Utilities;

public sealed class ScopedSecureMemory : IDisposable
{
    private byte[]? _data;
    private readonly bool _clearOnDispose;
    private bool _disposed;

    private ScopedSecureMemory(byte[] data, bool clearOnDispose = true)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
        _clearOnDispose = clearOnDispose;
    }

    public static ScopedSecureMemory Allocate(int size)
    {
        if (size <= 0)
            throw new ArgumentException("Size must be positive", nameof(size));

        return new ScopedSecureMemory(new byte[size]);
    }

    public static ScopedSecureMemory Wrap(byte[] data, bool clearOnDispose = true)
    {
        return new ScopedSecureMemory(data, clearOnDispose);
    }

    public Span<byte> AsSpan()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _data!.AsSpan();
    }

    public Memory<byte> AsMemory()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _data!.AsMemory();
    }

    public int Length => _data?.Length ?? 0;

    public void Dispose()
    {
        if (_disposed) return;

        if (_data != null && _clearOnDispose)
        {
            CryptographicOperations.ZeroMemory(_data);
        }

        _data = null;
        _disposed = true;
    }
}