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
            // IMPORTANT: If salt is longer than HMAC key size needed,
            // HMAC standard hashes it first. Sodium might do this internally,
            // but it's safer to handle if needed. However, SignHmacSha256 likely
            // REQUIRES a 32-byte key. Let's enforce that for the salt.
            if (salt.Length != HashOutputLength)
            {
                // Option 1: Throw - Simplest if you always provide 32-byte salt or default
                throw new ArgumentException($"Salt must be {HashOutputLength} bytes for SignHmacSha256.",
                    nameof(salt));

                // Option 2: Hash the salt if it's not 32 bytes (more complex)
                // _salt = Sodium.GenericHash.Hash(salt.ToArray(), null, HashOutputLength);
            }
            else
            {
                _salt = salt.ToArray();
            }
        }

        _disposed = false;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Expand(ReadOnlySpan<byte> info, Span<byte> output)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(HkdfSha256));
        if (output.Length > 255 * HashOutputLength) throw new ArgumentException("Output length too large");

        Span<byte> prk = stackalloc byte[HashOutputLength]; // PRK buffer - OK here

        try
        {
            // Extract PRK
            byte[] prkBytes = Sodium.SecretKeyAuth.SignHmacSha256(_ikm, _salt);
            if (prkBytes.Length != HashOutputLength)
                throw new CryptographicException("HMAC-SHA256 output size mismatch during PRK generation.");
            prkBytes.CopyTo(prk);
            Wipe(prkBytes);
        }
        catch (Exception ex)
        {
            throw new CryptographicException("HKDF-Extract (SignHmacSha256) failed during PRK generation.", ex);
        }

        // Expand PRK into output
        byte counter = 1;
        int bytesWritten = 0;
        int requiredInputSize = HashOutputLength + info.Length + 1;

        // --- Change: Always use heap allocation for inputBuffer in this context ---
        byte[] inputBufferHeap = new byte[requiredInputSize]; // Allocate on heap
        Span<byte> inputBufferSpan = inputBufferHeap; // Span points to heap array
        // --- End Change ---

        Span<byte> hash = stackalloc byte[HashOutputLength]; // T(n) buffer - OK here

        byte[] prkAsKey = new byte[HashOutputLength];
        byte[]? tempInputArray = null; // Reusable array for slice conversion
        byte[]? tempHashResult = null;

        try
        {
            prk.CopyTo(prkAsKey);

            while (bytesWritten < output.Length)
            {
                // Prepare input slice using inputBufferSpan (which points to heap)
                Span<byte> currentInputSlice;
                if (bytesWritten == 0)
                {
                    info.CopyTo(inputBufferSpan);
                    inputBufferSpan[info.Length] = counter;
                    currentInputSlice = inputBufferSpan.Slice(0, info.Length + 1);
                }
                else
                {
                    hash.CopyTo(inputBufferSpan);
                    info.CopyTo(inputBufferSpan.Slice(HashOutputLength));
                    inputBufferSpan[HashOutputLength + info.Length] = counter;
                    currentInputSlice = inputBufferSpan.Slice(0, HashOutputLength + info.Length + 1);
                }

                if (tempInputArray == null || tempInputArray.Length != currentInputSlice.Length)
                {
                    tempInputArray = new byte[currentInputSlice.Length];
                }

                currentInputSlice.CopyTo(tempInputArray);

                tempHashResult = Sodium.SecretKeyAuth.SignHmacSha256(
                    tempInputArray, 
                    prkAsKey
                );

                if (tempHashResult.Length != HashOutputLength)
                    throw new CryptographicException(
                        $"HMAC-SHA256 output size mismatch during T({counter}) generation.");

                tempHashResult.CopyTo(hash);
                Wipe(tempHashResult);
                tempHashResult = null;

                // Copy T(n) to output buffer
                int bytesToCopy = Math.Min(HashOutputLength, output.Length - bytesWritten);
                hash.Slice(0, bytesToCopy).CopyTo(output.Slice(bytesWritten));

                bytesWritten += bytesToCopy;
                counter++;
                // Clear the temp input array
                Wipe(tempInputArray); // Use Wipe for consistency
            }
        }
        finally
        {
            // Clear stack spans
            prk.Clear();
            hash.Clear();
            // No need to clear inputBufferSpan as it points to inputBufferHeap

            // Wipe heap buffers
            if (inputBufferHeap != null) Wipe(inputBufferHeap); // Wipe heap allocated input buffer
            if (prkAsKey != null) Wipe(prkAsKey);
            if (tempInputArray != null) Wipe(tempInputArray);
            // tempHashResult should be null here
        }
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
                if (_ikm != null) Wipe(_ikm);
                if (_salt != null) Wipe(_salt);
                _ikm = null!;
                _salt = null!;
            }

            _disposed = true;
        }
    }

    // Helper to abstract wiping - Use Sodium.Utilities or SodiumInterop helper
    private static void Wipe(byte[] buffer)
    {
        if (buffer == null) return;
        // If Sodium.Utilities is available and preferred:
        SodiumInterop.SecureWipe(buffer);
        // Or if using custom P/Invoke helper:
        // SodiumInterop.SecureWipe(buffer);
        // Or fallback (less secure):
        // Array.Clear(buffer, 0, buffer.Length);
    }
}