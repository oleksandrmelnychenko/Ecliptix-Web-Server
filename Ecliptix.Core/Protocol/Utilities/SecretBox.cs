namespace Ecliptix.Core.Protocol.Utilities;

using System;
using System.Runtime.InteropServices;

public sealed class SecretBox<T> : IDisposable where T : unmanaged
{
    private readonly IntPtr _data;
    private readonly int _size;
    private bool _disposed;

    public SecretBox(T value)
    {
        _size = Marshal.SizeOf<T>();
        _data = Marshal.AllocHGlobal(_size);
        Marshal.StructureToPtr(value, _data, false);
        _disposed = false;
    }

    public T ExposeSecret()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(SecretBox<T>));
        return Marshal.PtrToStructure<T>(_data);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            unsafe
            {
                byte* ptr = (byte*)_data;
                for (int i = 0; i < _size; i++) ptr[i] = 0;
            }
            Marshal.FreeHGlobal(_data);
            _disposed = true;
        }
    }

    public override string ToString() => "[SecretBox: Hidden]";
}

[StructLayout(LayoutKind.Sequential)]
public struct PrivateKey
{
    public unsafe fixed byte Key[Constants.X25519KeySize];
}