using System;
using System.Security.Cryptography;

namespace Ecliptix.Utilities;

public sealed class SecureBytes : IDisposable
{
    private byte[]? _buffer;

    private SecureBytes(byte[] buffer)
    {
        _buffer = buffer;
    }

    public ReadOnlySpan<byte> Span => _buffer ?? Array.Empty<byte>();

    public static SecureBytes From(byte[] buffer, bool takeOwnership = true)
    {
        if (buffer == null)
        {
            throw new ArgumentNullException(nameof(buffer));
        }

        return takeOwnership
            ? new SecureBytes(buffer)
            : new SecureBytes(buffer.AsSpan().ToArray());
    }

    public byte[] ToArray()
    {
        if (_buffer == null)
        {
            return Array.Empty<byte>();
        }

        byte[] copy = _buffer.AsSpan().ToArray();
        return copy;
    }

    public void Dispose()
    {
        if (_buffer == null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_buffer);
        _buffer = null;
    }
}
