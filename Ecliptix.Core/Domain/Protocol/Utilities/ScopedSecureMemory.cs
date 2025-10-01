using System.Buffers;
using System.Runtime.CompilerServices;
using Ecliptix.Utilities;

namespace Ecliptix.Core.Domain.Protocol.Utilities;

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

    public ReadOnlySpan<byte> AsReadOnlySpan()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _data!.AsSpan();
    }

    public Memory<byte> AsMemory()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _data!.AsMemory();
    }

    public byte[] ToArray()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (byte[])_data!.Clone();
    }

    public int Length => _data?.Length ?? 0;

    public void Dispose()
    {
        if (_disposed) return;

        if (_data != null && _clearOnDispose)
        {
            SodiumInterop.SecureWipe(_data);
        }

        _data = null;
        _disposed = true;
    }
}

public sealed class SecurePooledArray<T> : IDisposable where T : struct
{
    private T[]? _array;
    private readonly int _length;
    private bool _disposed;

    internal SecurePooledArray(T[] array, int length)
    {
        _array = array ?? throw new ArgumentNullException(nameof(array));
        _length = length;
    }

    public Span<T> AsSpan()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _array!.AsSpan(0, _length);
    }

    public ReadOnlySpan<T> AsReadOnlySpan()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _array!.AsSpan(0, _length);
    }

    public void Dispose()
    {
        if (_disposed || _array == null) return;
        _disposed = true;

        if (typeof(T) == typeof(byte))
        {
            byte[] byteArray = Unsafe.As<T[], byte[]>(ref _array);
            SodiumInterop.SecureWipe(byteArray);
        }
        else
        {
            Array.Clear(_array, 0, _array.Length);
        }

        ArrayPool<T>.Shared.Return(_array, clearArray: false);
        _array = null;
    }
}

public static class SecureArrayPool
{
    public static SecurePooledArray<T> Rent<T>(int minimumLength) where T : struct
    {
        T[] array = ArrayPool<T>.Shared.Rent(minimumLength);
        return new SecurePooledArray<T>(array, minimumLength);
    }
}