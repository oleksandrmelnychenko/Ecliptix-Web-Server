using System.Runtime.InteropServices;
using Ecliptix.Core.Protocol.Utilities;

namespace Ecliptix.Core.Protocol;

public static class SodiumInterop
{
    private const string LibSodium = "libsodium";

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    private static extern int sodium_init();

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal static extern IntPtr sodium_malloc(UIntPtr size);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal static extern void sodium_free(IntPtr ptr);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void sodium_memzero(IntPtr ptr, UIntPtr length);

    static SodiumInterop()
    {
        if (sodium_init() < 0)
            throw new InvalidOperationException("Failed to initialize libsodium.");
    }

    /// <summary>
    /// Securely wipes a byte array by overwriting it with zeros using libsodium.
    /// </summary>
    /// <param name="buffer">The byte array to wipe.</param>
    /// <returns>A Result indicating success or failure.</returns>
    public static Result<Unit, ShieldFailure> SecureWipe(byte[]? buffer)
    {
        if (buffer == null)
            return Result<Unit, ShieldFailure>.Err(ShieldFailure.InvalidInput("Buffer cannot be null"));
        if (buffer.Length == 0)
            return Result<Unit, ShieldFailure>.Ok(Unit.Value);

        GCHandle handle = default;
        try
        {
            handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            IntPtr ptr = handle.AddrOfPinnedObject();
            if (ptr == IntPtr.Zero)
                return Result<Unit, ShieldFailure>.Err(ShieldFailure.Generic("Failed to pin buffer memory"));
            sodium_memzero(ptr, (UIntPtr)buffer.Length);
            return Result<Unit, ShieldFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, ShieldFailure>.Err(ShieldFailure.Generic("Failed to wipe buffer", ex));
        }
        finally
        {
            if (handle.IsAllocated) handle.Free();
        }
    }
}