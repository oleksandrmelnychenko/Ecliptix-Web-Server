using System.Runtime.InteropServices;

namespace Ecliptix.Core.Protocol;

public static class SodiumInterop
{
    private const string LibSodium = "libsodium"; 

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal static extern IntPtr sodium_malloc(UIntPtr size);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal static extern void sodium_free(IntPtr ptr);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void sodium_memzero(IntPtr ptr, UIntPtr length);

    public static void SecureWipe(byte[]? buffer)
    {
        if (buffer == null || buffer.Length == 0) return;
        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            sodium_memzero(handle.AddrOfPinnedObject(), (UIntPtr)buffer.Length);
        }
        finally
        {
            if (handle.IsAllocated) handle.Free();
        }
    }
}