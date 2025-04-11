using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace Ecliptix.Core.Protocol;

public sealed class SodiumSecureMemoryHandle : SafeHandle
{
    public int Length { get; }

    private SodiumSecureMemoryHandle(IntPtr preexistingHandle, int length, bool ownsHandle)
        : base(invalidHandleValue: IntPtr.Zero, ownsHandle: ownsHandle)
    {
        SetHandle(preexistingHandle);
        Length = length;
    }

    public static SodiumSecureMemoryHandle Allocate(int length)
    {
        switch (length)
        {
            case < 0:
                throw new ArgumentOutOfRangeException(nameof(length));
            case 0:
                return new SodiumSecureMemoryHandle(IntPtr.Zero, 0, true);
        }

        UIntPtr size = (UIntPtr)length;
        IntPtr ptr = SodiumInterop.sodium_malloc(size);
        if (ptr == IntPtr.Zero)
        {
            throw new OutOfMemoryException($"sodium_malloc failed to allocate {length} bytes.");
        }

        return new SodiumSecureMemoryHandle(ptr, length, true);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    public void Write(ReadOnlySpan<byte> data)
    {
        if (!IsInvalid && !IsClosed)
        {
            if (data.Length > Length)
                throw new ArgumentException("Data length exceeds allocated buffer size.", nameof(data));

            bool success = false;
            DangerousAddRef(ref success);
            try
            {
                unsafe
                {
                    fixed (byte* pData = data)
                    {
                        Buffer.MemoryCopy(pData, (void*)handle, Length, data.Length);
                    }
                }
            }
            finally
            {
                DangerousRelease();
            }
        }
        else
        {
            throw new ObjectDisposedException(nameof(SodiumSecureMemoryHandle));
        }
    }

    public void Read(Span<byte> destination)
    {
        if (!IsInvalid && !IsClosed)
        {
            if (destination.Length < Length)
                throw new ArgumentException("Destination buffer is smaller than the allocated size.",
                    nameof(destination));

            bool success = false;
            DangerousAddRef(ref success);
            try
            {
                unsafe
                {
                    fixed (byte* pDest = destination)
                    {
                        Buffer.MemoryCopy((void*)handle, pDest, destination.Length, Length);
                    }
                }
            }
            finally
            {
                DangerousRelease();
            }
        }
        else
        {
            throw new ObjectDisposedException(nameof(SodiumSecureMemoryHandle));
        }
    }
    
    public byte[] ReadBytes(int length)
    {
        if (IsInvalid || IsClosed)
            throw new ObjectDisposedException(nameof(SodiumSecureMemoryHandle));
        if (length > Length)
            throw new ArgumentException("Requested length exceeds allocated size.", nameof(length));

        byte[] buffer = new byte[length];
        bool success = false;
        DangerousAddRef(ref success);
        try
        {
            unsafe
            {
                fixed (byte* pBuffer = buffer)
                {
                    Buffer.MemoryCopy((void*)handle, pBuffer, length, length);
                }
            }
        }
        finally
        {
            DangerousRelease();
        }
        return buffer;
    }

    protected override bool ReleaseHandle()
    {
        if (!IsInvalid)
        {
            SodiumInterop.sodium_free(handle);
        }

        return true;
    }
}