using System.Runtime.InteropServices;

public static class SodiumInterop
{
    private const string LibSodium = "libsodium"; // Adjust if your lib name differs

    // size_t sodium_malloc(size_t size);
    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal static extern IntPtr sodium_malloc(UIntPtr size);

    // void sodium_free(void *ptr);
    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal static extern void sodium_free(IntPtr ptr);

    // void sodium_memzero(void *const pnt, const size_t len); // Keep for temporary buffer wiping
    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern void sodium_memzero(IntPtr ptr, UIntPtr length);

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