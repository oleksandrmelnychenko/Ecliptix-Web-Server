using System.Buffers;
using Ecliptix.Core.Observability;
using Microsoft.Extensions.Logging;

namespace Ecliptix.Core.Api.Grpc.Base;

public class EncryptionContext
{
    private byte[]? _buffer;

    public byte[] GetBuffer(int minimumSize)
    {
        if (_buffer == null || _buffer.Length < minimumSize)
        {
            if (_buffer != null)
            {
                ArrayPool<byte>.Shared.Return(_buffer);
            }
            _buffer = ArrayPool<byte>.Shared.Rent(minimumSize);
        }
        return _buffer;
    }

    public void Reset()
    {
        if (_buffer != null)
        {
            Array.Clear(_buffer, 0, _buffer.Length);
        }
    }

    public void Dispose()
    {
        if (_buffer != null)
        {
            ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
            _buffer = null;
        }
    }
}