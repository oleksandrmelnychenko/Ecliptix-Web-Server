using System.Runtime.InteropServices;
using Ecliptix.Core.Protocol.Failures;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Protocol;

public static class SodiumInterop
{
    private const string LibSodium = "libsodium";

    private const int MaxBufferSize = 1_000_000_000;

    private const int SmallBufferThreshold = 64;

    private static readonly Result<Unit, SodiumFailure> InitializationResult;

    static SodiumInterop()
    {
        InitializationResult = InitializeSodium();
    }

    public static bool IsInitialized => InitializationResult.IsOk;

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    private static extern int sodium_init();

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal static extern IntPtr sodium_malloc(UIntPtr size);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal static extern void sodium_free(IntPtr ptr);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void sodium_memzero(IntPtr ptr, UIntPtr length);

    private static Result<Unit, SodiumFailure> InitializeSodium()
    {
        return Result<Unit, SodiumFailure>.Try(
            () =>
            {
                int result = sodium_init();
                const int dllImportSuccess = 0;
                if (result < dllImportSuccess)
                    throw new InvalidOperationException(SodiumFailureMessages.SodiumInitFailed);
            },
            ex => ex switch
            {
                DllNotFoundException dllEx => SodiumFailure.LibraryNotFound(
                    string.Format(SodiumFailureMessages.LibraryLoadFailed, LibSodium), dllEx),
                InvalidOperationException opEx when opEx.Message.Contains(SodiumExceptionMessagePatterns
                        .SodiumInitPattern) =>
                    SodiumFailure.InitializationFailed(SodiumFailureMessages.InitializationFailed, opEx),
                _ => SodiumFailure.InitializationFailed(SodiumFailureMessages.UnexpectedInitError, ex)
            }
        );
    }

    public static Result<Unit, SodiumFailure> SecureWipe(byte[]? buffer)
    {
        if (!IsInitialized)
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.InitializationFailed(SodiumFailureMessages.NotInitialized));

        return Result<byte[], SodiumFailure>
            .FromValue(buffer, SodiumFailure.BufferTooSmall(SodiumFailureMessages.BufferNull))
            .Bind(nonNullBuffer => nonNullBuffer switch
            {
                { Length: 0 } => Result<Unit, SodiumFailure>.Ok(Unit.Value),
                _ => Result<byte[], SodiumFailure>.Validate(
                        nonNullBuffer,
                        buf => buf.Length <= MaxBufferSize,
                        SodiumFailure.BufferTooLarge(
                            string.Format(SodiumFailureMessages.BufferTooLarge, nonNullBuffer.Length, MaxBufferSize)))
                    .Bind(validBuffer => validBuffer.Length <= SmallBufferThreshold
                        ? WipeSmallBuffer(validBuffer)
                        : WipeLargeBuffer(validBuffer))
            });
    }

    private static Result<Unit, SodiumFailure> WipeSmallBuffer(byte[] buffer)
    {
        return Result<Unit, SodiumFailure>.Try(
            () => { Array.Clear(buffer, 0, buffer.Length); },
            ex =>
                SodiumFailure.SecureWipeFailed(
                    string.Format(SodiumFailureMessages.SmallBufferClearFailed, buffer.Length), ex));
    }

    private static Result<Unit, SodiumFailure> WipeLargeBuffer(byte[] buffer)
    {
        GCHandle handle = default;
        return Result<Unit, SodiumFailure>.Try(
            () =>
            {
                handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                IntPtr ptr = handle.AddrOfPinnedObject();
                if (ptr == IntPtr.Zero && buffer.Length > 0)
                    throw new InvalidOperationException(SodiumFailureMessages.AddressOfPinnedObjectFailed);

                sodium_memzero(ptr, (UIntPtr)buffer.Length);
            },
            ex => ex switch
            {
                ArgumentException argEx => SodiumFailure.MemoryPinningFailed(
                    SodiumFailureMessages.PinningFailed, argEx),
                OutOfMemoryException oomEx => SodiumFailure.MemoryPinningFailed(
                    SodiumFailureMessages.InsufficientMemory, oomEx),
                InvalidOperationException opEx when opEx.Message.Contains(SodiumExceptionMessagePatterns
                        .AddressPinnedObjectPattern) =>
                    SodiumFailure.MemoryPinningFailed(SodiumFailureMessages.GetPinnedAddressFailed, opEx),
                _ => SodiumFailure.MemoryPinningFailed(
                    string.Format(SodiumFailureMessages.SecureWipeFailed, buffer.Length), ex)
            },
            () =>
            {
                if (handle.IsAllocated) handle.Free();
            }
        );
    }
}