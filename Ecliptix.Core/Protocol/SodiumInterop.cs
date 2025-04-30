using System.Runtime.InteropServices;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Protocol;

public static class SodiumInterop
{
    private const string LibSodium = "libsodium";
    
    private const int MaxBufferSize = 1_000_000_000;
    
    private const int SmallBufferThreshold = 64;

    public static bool IsInitialized { get; }

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
        try
        {
            if (sodium_init() < 0)
            {
                throw new InvalidOperationException("sodium_init() returned an error code.");
            }

            IsInitialized = true;
        }
        catch (DllNotFoundException dllEx)
        {
            throw new InvalidOperationException(
                $"Failed to load {LibSodium}. Ensure the native library is available and compatible.", dllEx);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("An unexpected error occurred during libsodium initialization.", ex);
        }
    }

    public static Result<Unit, ShieldFailure> SecureWipe(byte[]? buffer) =>
        Result<byte[], ShieldFailure>.FromValue(buffer, ShieldFailure.InvalidInput("Buffer cannot be null."))
            .Bind(nonNullBuffer => nonNullBuffer switch
            {
                { Length: 0 } => Result<Unit, ShieldFailure>.Ok(Unit.Value),
                _ => Result<byte[], ShieldFailure>.Validate(
                        nonNullBuffer,
                        buf => buf.Length <= MaxBufferSize,
                        ShieldFailure.InvalidInput(
                            $"Buffer size ({nonNullBuffer.Length:N0} bytes) exceeds maximum ({MaxBufferSize:N0} bytes)."))
                    .Bind(validBuffer => validBuffer.Length <= SmallBufferThreshold
                        ? WipeSmallBuffer(validBuffer)
                        : WipeLargeBuffer(validBuffer))
            });

    private static Result<Unit, ShieldFailure> WipeSmallBuffer(byte[] buffer) =>
        Result<Unit, ShieldFailure>.Try(
            action: () => { Array.Clear(buffer, 0, buffer.Length); },
            errorMapper: ex =>
                ShieldFailure.DataAccess(
                    $"Failed to clear small buffer ({buffer.Length} bytes) using Array.Clear.", ex));

    private static Result<Unit, ShieldFailure> WipeLargeBuffer(byte[] buffer)
    {
        GCHandle handle = default;
        return Result<Unit, ShieldFailure>.Try(
            action: () =>
            {
                handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                IntPtr ptr = handle.AddrOfPinnedObject();
                if (ptr == IntPtr.Zero && buffer.Length > 0)
                {
                    throw new InvalidOperationException(
                        "GCHandle.Alloc succeeded, but AddrOfPinnedObject returned IntPtr.Zero for a non-empty buffer.");
                }

                sodium_memzero(ptr, (UIntPtr)buffer.Length);
            },
            errorMapper: ex => ex switch
            {
                ArgumentException argEx => ShieldFailure.PinningFailure(
                    "Failed to pin buffer memory (GCHandle.Alloc). Invalid buffer or handle type.", argEx),
                OutOfMemoryException oomEx => ShieldFailure.PinningFailure(
                    "Insufficient memory to pin buffer (GCHandle.Alloc).", oomEx),
                InvalidOperationException opEx when opEx.Message.Contains("AddrOfPinnedObject returned IntPtr.Zero") =>
                    ShieldFailure.PinningFailure("Failed to get address of pinned buffer.", opEx),
                not null => ShieldFailure.DataAccess(
                    $"Unexpected error during secure wipe via sodium_memzero ({buffer.Length} bytes).", ex)
            },
            cleanup: () =>
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        );
    }
}