using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Sodium;

namespace Ecliptix.Core.Protocol;

public sealed class Hkdf : IDisposable
{
    private const int HashOutputLength = 32;
    private byte[] _ikm;
    private byte[] _salt;
    private bool _disposed;
    private readonly HashAlgorithmType _algorithm;

    public Hkdf(ReadOnlySpan<byte> ikm, HashAlgorithmType algorithm, ReadOnlySpan<byte> salt = default)
    {
        SodiumCore.Init();
        _ikm = ikm.ToArray();
        _algorithm = algorithm;

        if (salt.IsEmpty)
        {
            _salt = new byte[HashOutputLength];
        }
        else
        {
            if (salt.Length != HashOutputLength)
            {
                throw new ArgumentException($"Salt must be {HashOutputLength} bytes for {_algorithm}.", nameof(salt));
            }
            _salt = salt.ToArray();
        }

        _disposed = false;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Expand(ReadOnlySpan<byte> info, Span<byte> output)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(Hkdf));
        if (output.Length > 255 * HashOutputLength) throw new ArgumentException("Output length too large");

        Span<byte> prk = stackalloc byte[HashOutputLength];

        try
        {
            byte[]? prkBytes = _algorithm == HashAlgorithmType.Sha256
                ? SecretKeyAuth.SignHmacSha256(_ikm, _salt)
                : ComputeSha3Hmac(_ikm, _salt);
            if (prkBytes.Length != HashOutputLength)
                throw new CryptographicException($"HMAC-{_algorithm} output size mismatch during PRK generation.");
            prkBytes.CopyTo(prk);
            Wipe(prkBytes);
        }
        catch (Exception ex)
        {
            throw new CryptographicException($"HKDF-Extract (HMAC-{_algorithm}) failed during PRK generation.", ex);
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

                byte[] tempHashResult = _algorithm == HashAlgorithmType.Sha256
                    ? SecretKeyAuth.SignHmacSha256(tempInputArray, prkAsKey)
                    : ComputeSha3Hmac(tempInputArray, prkAsKey);

                if (tempHashResult.Length != HashOutputLength)
                    throw new CryptographicException(
                        $"HMAC-{_algorithm} output size mismatch during T({counter}) generation.");

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
            if (tempInputArray != null) Wipe(tempInputArray);
        }
    }

    private static byte[] ComputeSha3Hmac(byte[] message, byte[] key)
    {
        using SHA3_256 sha3 = SHA3_256.Create();
        byte[] keyHash = sha3.ComputeHash(key);
        byte[] paddedKey = new byte[sha3.InputBlockSize / 8];
        for (int i = 0; i < keyHash.Length && i < paddedKey.Length; i++)
        {
            paddedKey[i] = keyHash[i];
        }

        byte[] innerPad = new byte[paddedKey.Length];
        byte[] outerPad = new byte[paddedKey.Length];
        for (int i = 0; i < paddedKey.Length; i++)
        {
            innerPad[i] = (byte)(paddedKey[i] ^ 0x36);
            outerPad[i] = (byte)(paddedKey[i] ^ 0x5C);
        }

        using SHA3_256 innerSha3 = SHA3_256.Create();
        innerSha3.TransformBlock(innerPad, 0, innerPad.Length, null, 0);
        innerSha3.TransformFinalBlock(message, 0, message.Length);
        byte[] innerHash = innerSha3.Hash!;

        using SHA3_256 outerSha3 = SHA3_256.Create();
        outerSha3.TransformBlock(outerPad, 0, outerPad.Length, null, 0);
        outerSha3.TransformFinalBlock(innerHash, 0, innerHash.Length);
        byte[] result = outerSha3.Hash!;

        Wipe(innerPad);
        Wipe(outerPad);
        Wipe(innerHash);
        return result;
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