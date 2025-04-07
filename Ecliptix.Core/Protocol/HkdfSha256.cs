using System;
using System.Runtime.CompilerServices;
using Sodium;

namespace Ecliptix.Core.Protocol
{
    public sealed class HkdfSha256(ReadOnlySpan<byte> key) : IDisposable
    {
        private readonly byte[] _key = key.ToArray();
        private bool _disposed = false;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Expand(ReadOnlySpan<byte> info, Span<byte> output)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(HkdfSha256));

            // Extract PRK (pseudorandom key)
            Span<byte> prk = stackalloc byte[32];
            Sodium.SecretKeyAuth.SignHmacSha256([], _key).AsSpan().CopyTo(prk);

            // Expand PRK into output
            byte counter = 1;
            int bytesWritten = 0;
            Span<byte> input = stackalloc byte[32 + info.Length + 1];
            Span<byte> hash = stackalloc byte[32];

            while (bytesWritten < output.Length)
            {
                if (bytesWritten > 0) hash[..32].CopyTo(input);
                info.CopyTo(input[hash.Length..]);
                input[hash.Length + info.Length] = counter++;

                // Use SignHmacSha256 with byte[] and copy result to hash
                Sodium.SecretKeyAuth.SignHmacSha256(input.ToArray(), prk.ToArray()).AsSpan().CopyTo(hash);

                int bytesToCopy = Math.Min(hash.Length, output.Length - bytesWritten);
                hash[..bytesToCopy].CopyTo(output[bytesWritten..]);
                bytesWritten += bytesToCopy;
            }

            prk.Clear();
            input.Clear();
            hash.Clear();
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Array.Clear(_key, 0, _key.Length);
                _disposed = true;
            }
        }
    }
}