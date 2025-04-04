using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Security;
using Sodium;
using Sodium.Exceptions;

namespace Ecliptix.Core.Protocol;

public sealed class HkdfSha256(ReadOnlySpan<byte> inputKeyMaterial) : IDisposable
{
    private byte[]? _ikm = inputKeyMaterial.ToArray();
    private bool _disposed;
    private const int HashLen = 32;

    private static byte[] Extract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> ikm)
    {
        try
        {
            byte[]? prkBytes;
            if (salt.IsEmpty)
            {
                Span<byte> zeroSalt = stackalloc byte[HashLen];
                byte[] ikmBytes = ikm.ToArray();
                prkBytes = SecretKeyAuth.SignHmacSha256(zeroSalt.ToArray(), ikmBytes);
                Array.Clear(ikmBytes, 0, ikmBytes.Length);
            }
            else
            {
                byte[] saltBytes = salt.ToArray();
                byte[] ikmBytes = ikm.ToArray();
                prkBytes = SecretKeyAuth.SignHmacSha256(saltBytes, ikmBytes);
                Array.Clear(saltBytes, 0, saltBytes.Length);
                Array.Clear(ikmBytes, 0, ikmBytes.Length);
            }
            if (prkBytes is not { Length: HashLen })
            {
                throw new SecurityException("Invalid HMAC result.");
            }
            return prkBytes;
        }
        catch (Exception ex) when (ex is KeyOutOfRangeException or SEHException or DllNotFoundException)
        {
            throw new InvalidOperationException("HKDF-Extract phase failed.", ex);
        }
    }

    private static void ExpandInternal(byte[] prk, ReadOnlySpan<byte> info, Span<byte> okm)
    {
        if (okm.Length > 255 * HashLen)
        {
            throw new ArgumentException("Output length too long.", nameof(okm));
        }
        
        if (prk is not { Length: HashLen })
        {
            throw new ArgumentException("Invalid PRK.", nameof(prk));
        }
        
        byte[] currentT = [];
        int generated = 0;
        byte counter = 1;
        byte[] infoBytes = info.ToArray();
        byte[]? buffer = null;
        try
        {
            while (generated < okm.Length)
            {
                int bufferLen = currentT.Length + infoBytes.Length + 1;
                buffer = new byte[bufferLen];
                Buffer.BlockCopy(currentT, 0, buffer, 0, currentT.Length);
                Buffer.BlockCopy(infoBytes, 0, buffer, currentT.Length, infoBytes.Length);
                buffer[bufferLen - 1] = counter;
                byte[] hmacResult = SecretKeyAuth.SignHmacSha256(prk, buffer);
                if (hmacResult.Length != HashLen)
                {
                    throw new Exception("Invalid HMAC result.");
                }
                int bytesToCopy = Math.Min(HashLen, okm.Length - generated);
                hmacResult.AsSpan(0, bytesToCopy).CopyTo(okm.Slice(generated, bytesToCopy));
                generated += bytesToCopy;
                currentT = hmacResult;
                Array.Clear(buffer, 0, buffer.Length);
                buffer = null;
                counter++;
                if (counter == 0) throw new OverflowException("Counter overflow.");
            }
        }
        catch (Exception ex) when (
            ex is MacOutOfRangeException or KeyOutOfRangeException or SEHException or DllNotFoundException or OverflowException
        )
        {
            throw new InvalidOperationException("HKDF-Expand phase failed.", ex);
        }
        finally
        {
            Array.Clear(currentT, 0, currentT.Length);
            Array.Clear(infoBytes, 0, infoBytes.Length);
            if (buffer != null) Array.Clear(buffer, 0, buffer.Length);
        }
    }

    public void Expand(ReadOnlySpan<byte> info, Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(_disposed || _ikm is null, this);
        byte[]? prk = null;
        try
        {
            prk = Extract(ReadOnlySpan<byte>.Empty, _ikm);
            ExpandInternal(prk, info, output);
        }
        finally
        {
            if (prk != null) Array.Clear(prk, 0, prk.Length);
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_ikm != null)
            {
                Array.Clear(_ikm, 0, _ikm.Length);
                _ikm = null;
            }
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}