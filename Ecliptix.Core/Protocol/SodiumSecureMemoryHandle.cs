using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace Ecliptix.Core.Protocol;

public sealed class SodiumSecureMemoryHandle : SafeHandle
{
    public int Length { get; }

    // Private constructor for factory method
    private SodiumSecureMemoryHandle(IntPtr preexistingHandle, int length, bool ownsHandle)
        : base(invalidHandleValue: IntPtr.Zero, ownsHandle: ownsHandle)
    {
        SetHandle(preexistingHandle);
        Length = length;
    }

    // Public factory method to allocate secure memory
    public static SodiumSecureMemoryHandle Allocate(int length)
    {
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
        if (length == 0) return new SodiumSecureMemoryHandle(IntPtr.Zero, 0, true); // Handle zero length

        UIntPtr size = (UIntPtr)length;
        IntPtr ptr = SodiumInterop.sodium_malloc(size);
        if (ptr == IntPtr.Zero)
        {
            // Maybe throw OutOfMemoryException or a custom allocation failed exception
            throw new OutOfMemoryException($"sodium_malloc failed to allocate {length} bytes.");
        }

        return new SodiumSecureMemoryHandle(ptr, length, true);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    // Method to securely copy data INTO the protected memory
    public void Write(ReadOnlySpan<byte> data)
    {
        if (IsInvalid || IsClosed) throw new ObjectDisposedException(nameof(SodiumSecureMemoryHandle));
        if (data.Length > Length)
            throw new ArgumentException("Data length exceeds allocated buffer size.", nameof(data));

        bool success = false;
        DangerousAddRef(ref success);
        try
        {
            // Use Marshal.Copy for simplicity, or unsafe code for potential perf gain
            unsafe // Requires "Allow unsafe code" in project settings
            {
                fixed (byte* pData = data)
                {
                    Buffer.MemoryCopy(pData, (void*)handle, Length, data.Length);
                }
            }
            // Non-unsafe alternative:
            // Marshal.Copy(data.ToArray(), 0, handle, data.Length); // Creates temp array
        }
        finally
        {
            DangerousRelease();
        }
    }

    // Method to provide temporary access to the memory as a Span
    // WARNING: The Span is only valid as long as the handle is AddRef'd
    public unsafe Span<byte> GetSpan() // Requires "Allow unsafe code"
    {
        if (IsInvalid || IsClosed) throw new ObjectDisposedException(nameof(SodiumSecureMemoryHandle));
        // Note: No AddRef/Release here. Caller must ensure handle lifetime.
        // This is simpler but requires more care from the caller.
        // A safer approach involves returning a custom ref struct that holds the AddRef/Release.
        return new Span<byte>((void*)handle, Length);
    }

    // Method to securely copy data OUT OF the protected memory
    public void Read(Span<byte> destination)
    {
        if (IsInvalid || IsClosed) throw new ObjectDisposedException(nameof(SodiumSecureMemoryHandle));
        if (destination.Length < Length)
            throw new ArgumentException("Destination buffer is smaller than the allocated size.", nameof(destination));

        bool success = false;
        DangerousAddRef(ref success);
        try
        {
            unsafe // Requires "Allow unsafe code" in project settings
            {
                fixed (byte* pDest = destination)
                {
                    Buffer.MemoryCopy((void*)handle, pDest, destination.Length, Length);
                }
            }
            // Non-unsafe alternative:
            // Marshal.Copy(handle, destination.ToArray(), 0, Length); // Creates temp array if needed? Check Span Marshal Copy
            // Marshal.Copy(handle, arr, 0, Length); // If destination IS an array
        }
        finally
        {
            DangerousRelease();
        }
    }


    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
    protected override bool ReleaseHandle()
    {
        // handle is the IntPtr pointing to the sodium_malloc'd memory
        if (!IsInvalid) // Check IsInvalid property here
        {
            SodiumInterop.sodium_free(handle);
            // handle is automatically set to IntPtr.Zero or the invalid handle value by the base class
        }

        return true; // Indicate successful release
    }
}