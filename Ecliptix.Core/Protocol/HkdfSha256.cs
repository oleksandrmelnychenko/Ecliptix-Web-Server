using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography; // For CryptographicException
using Sodium;

namespace Ecliptix.Core.Protocol;

public sealed class HkdfSha256 : IDisposable
{
    private const int HashOutputLength = 32;
    private byte[] _ikm;
    private byte[] _salt;
    private bool _disposed;

    public HkdfSha256(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt = default)
    {
        SodiumCore.Init();
        _ikm = ikm.ToArray();

        if (salt.IsEmpty)
        {
            _salt = new byte[HashOutputLength];
        }
        else
        {
            if (salt.Length != HashOutputLength)
            {
                throw new ArgumentException($"Salt must be {HashOutputLength} bytes for SignHmacSha256.",
                    nameof(salt));
            }

            _salt = salt.ToArray();
        }

        _disposed = false;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Expand(ReadOnlySpan<byte> info, Span<byte> output)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(HkdfSha256));
        if (output.Length > 255 * HashOutputLength) throw new ArgumentException("Output length too large");

        Span<byte> prk = stackalloc byte[HashOutputLength];

        try
        {
            byte[] prkBytes = SecretKeyAuth.SignHmacSha256(_ikm, _salt);
            if (prkBytes.Length != HashOutputLength)
                throw new CryptographicException("HMAC-SHA256 output size mismatch during PRK generation.");
            prkBytes.CopyTo(prk);
            Wipe(prkBytes);
        }
        catch (Exception ex)
        {
            throw new CryptographicException("HKDF-Extract (SignHmacSha256) failed during PRK generation.", ex);
        }

        byte counter = 1;
        int bytesWritten = 0;
        int requiredInputSize = HashOutputLength + info.Length + 1;

        byte[] inputBufferHeap = new byte[requiredInputSize];
        Span<byte> inputBufferSpan = inputBufferHeap;
        Span<byte> hash = stackalloc byte[HashOutputLength];

        byte[] prkAsKey = new byte[HashOutputLength];
        byte[]? tempInputArray = null;

        try
        {
            prk.CopyTo(prkAsKey);

            while (bytesWritten < output.Length)
            {
                Span<byte> currentInputSlice;
                if (bytesWritten == 0)
                {
                    info.CopyTo(inputBufferSpan);
                    inputBufferSpan[info.Length] = counter;
                    currentInputSlice = inputBufferSpan[..(info.Length + 1)];
                }
                else
                {
                    hash.CopyTo(inputBufferSpan);
                    info.CopyTo(inputBufferSpan[HashOutputLength..]);
                    inputBufferSpan[HashOutputLength + info.Length] = counter;
                    currentInputSlice = inputBufferSpan[..(HashOutputLength + info.Length + 1)];
                }

                if (tempInputArray == null || tempInputArray.Length != currentInputSlice.Length)
                {
                    tempInputArray = new byte[currentInputSlice.Length];
                }

                currentInputSlice.CopyTo(tempInputArray);

                byte[] tempHashResult = SecretKeyAuth.SignHmacSha256(
                    tempInputArray,
                    prkAsKey
                );

                if (tempHashResult.Length != HashOutputLength)
                {
                    throw new CryptographicException(
                        $"HMAC-SHA256 output size mismatch during T({counter}) generation.");
                }

                tempHashResult.CopyTo(hash);
                Wipe(tempHashResult);

                int bytesToCopy = Math.Min(HashOutputLength, output.Length - bytesWritten);
                hash[..bytesToCopy].CopyTo(output[bytesWritten..]);

                bytesWritten += bytesToCopy;
                counter++;
                Wipe(tempInputArray);
            }
        }
        finally
        {
            prk.Clear();
            hash.Clear();

            Wipe(inputBufferHeap);
            Wipe(prkAsKey);
            if (tempInputArray != null)
            {
                Wipe(tempInputArray);
            }
        }
    }

    public void Dispose()
    {
        Dispose(true);
    }

    private void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                Wipe(_ikm);
                Wipe(_salt);
                _ikm = null!;
                _salt = null!;
            }

            _disposed = true;
        }
    }

    private static void Wipe(byte[] buffer) =>
        SodiumInterop.SecureWipe(buffer);
}