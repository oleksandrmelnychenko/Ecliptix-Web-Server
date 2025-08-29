using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Ecliptix.Core.Domain.Protocol.Failures;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Domain.Protocol;

public sealed class SodiumSecureMemoryHandle : SafeHandle
{

    public int Length { get; }

    public override bool IsInvalid => handle == IntPtr.Zero;

    private SodiumSecureMemoryHandle(IntPtr preexistingHandle, int length, bool ownsHandle)
        : base(IntPtr.Zero, ownsHandle)
    {
        SetHandle(preexistingHandle);
        Length = length;
    }

    public static Result<SodiumSecureMemoryHandle, SodiumFailure> Allocate(int length)
    {
        switch (length)
        {
            case < 0:
                return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(
                    SodiumFailure.InvalidBufferSize(string.Format(SodiumFailureMessages.NegativeAllocationLength,
                        length)));
            case 0:
                return Result<SodiumSecureMemoryHandle, SodiumFailure>.Ok(
                    new SodiumSecureMemoryHandle(IntPtr.Zero, 0, true));
        }

        if (!SodiumInterop.IsInitialized)
            return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(
                SodiumFailure.InitializationFailed(SodiumFailureMessages.SodiumNotInitialized));

        Result<IntPtr, SodiumFailure> allocationResult = ExecuteWithErrorHandling(
            () => SodiumInterop.sodium_malloc((UIntPtr)length),
            ex => SodiumFailure.AllocationFailed(
                string.Format(SodiumFailureMessages.UnexpectedAllocationError, length), ex)
        );

        if (allocationResult.IsErr)
            return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(allocationResult.UnwrapErr());

        IntPtr ptr = allocationResult.Unwrap();
        if (ptr == IntPtr.Zero)
            return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(
                SodiumFailure.AllocationFailed(string.Format(SodiumFailureMessages.AllocationFailed,
                    length)));

        return Result<SodiumSecureMemoryHandle, SodiumFailure>.Ok(
            new SodiumSecureMemoryHandle(ptr, length, true));
    }

    public Result<Unit, SodiumFailure> Write(ReadOnlySpan<byte> data)
    {
        if (IsInvalid || IsClosed)
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.NullPointer("Handle disposed"));

        if (data.Length > Length)
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.BufferTooLarge($"Data ({data.Length}) > buffer ({Length})"));

        if (data.IsEmpty) return Result<Unit, SodiumFailure>.Ok(Unit.Value);

        bool success = false;
        try
        {
            DangerousAddRef(ref success);
            if (!success)
                return Result<Unit, SodiumFailure>.Err(
                    SodiumFailure.MemoryPinningFailed("Ref count failed"));

            unsafe
            {
                Buffer.MemoryCopy(
                    Unsafe.AsPointer(ref MemoryMarshal.GetReference(data)),
                    (void*)handle,
                    Length,
                    data.Length);
            }

            return Result<Unit, SodiumFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.MemoryProtectionFailed("Unexpected write error", ex));
        }
        finally
        {
            if (success) DangerousRelease();
        }
    }

    public Result<Unit, SodiumFailure> Read(Span<byte> destination)
    {
        if (IsInvalid || IsClosed)
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.NullPointer(string.Format(SodiumFailureMessages.ObjectDisposed,
                    nameof(SodiumSecureMemoryHandle))));

        if (destination.Length < Length)
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.BufferTooSmall(
                    string.Format(SodiumFailureMessages.BufferTooSmall, destination.Length, Length)));

        if (Length == 0) return Result<Unit, SodiumFailure>.Ok(Unit.Value);

        bool success = false;
        try
        {
            DangerousAddRef(ref success);
            if (!success)
                return Result<Unit, SodiumFailure>.Err(
                    SodiumFailure.MemoryPinningFailed(SodiumFailureMessages.ReferenceCountFailed));

            if (IsInvalid || IsClosed)
                return Result<Unit, SodiumFailure>.Err(
                    SodiumFailure.NullPointer(
                        string.Format(SodiumFailureMessages.DisposedAfterAddRef, nameof(SodiumSecureMemoryHandle))));

            unsafe
            {
                Buffer.MemoryCopy(
                    (void*)handle,
                    Unsafe.AsPointer(ref MemoryMarshal.GetReference(destination)),
                    (ulong)destination.Length,
                    (ulong)Length);
            }

            return Result<Unit, SodiumFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.MemoryProtectionFailed(SodiumFailureMessages.UnexpectedReadError, ex));
        }
        finally
        {
            if (success) DangerousRelease();
        }
    }

    public Result<byte[], SodiumFailure> ReadBytes(int length)
    {
        if (IsInvalid || IsClosed)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.NullPointer(string.Format(SodiumFailureMessages.ObjectDisposed,
                    nameof(SodiumSecureMemoryHandle))));

        if (length < 0)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidBufferSize(string.Format(SodiumFailureMessages.NegativeReadLength, length)));

        if (length > Length)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.BufferTooSmall(string.Format(SodiumFailureMessages.ReadLengthExceedsSize,
                    length,
                    Length)));

        if (length == 0) return Result<byte[], SodiumFailure>.Ok([]);

        byte[] buffer = new byte[length];
        bool success = false;

        Result<byte[], SodiumFailure> copyResult = ExecuteWithErrorHandling(
            () =>
            {
                DangerousAddRef(ref success);
                if (!success) throw new InvalidOperationException(SodiumFailureMessages.ReferenceCountFailed);

                if (IsInvalid || IsClosed)
                    throw new ObjectDisposedException(
                        string.Format(SodiumFailureMessages.DisposedAfterAddRef, nameof(SodiumSecureMemoryHandle)));

                unsafe
                {
                    Buffer.MemoryCopy(
                        (void*)handle,
                        Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer.AsSpan())),
                        (ulong)length,
                        (ulong)length);
                }

                return buffer;
            },
            ex => ex switch
            {
                InvalidOperationException { Message: SodiumFailureMessages.ReferenceCountFailed } =>
                    SodiumFailure.MemoryPinningFailed(SodiumFailureMessages.ReferenceCountFailed),
                ObjectDisposedException => SodiumFailure.NullPointer(
                    string.Format(SodiumFailureMessages.DisposedAfterAddRef, nameof(SodiumSecureMemoryHandle))),
                _ => SodiumFailure.MemoryProtectionFailed(
                    string.Format(SodiumFailureMessages.UnexpectedReadBytesError, length), ex)
            }
        );

        if (success) DangerousRelease();

        return copyResult;
    }

    protected override bool ReleaseHandle()
    {
        if (IsInvalid) return true;

        SodiumInterop.sodium_free(handle);
        SetHandleAsInvalid();
        return true;
    }

    private static Result<T, SodiumFailure> ExecuteWithErrorHandling<T>(
        Func<T> action,
        Func<Exception, SodiumFailure> errorMapper)
    {
        try
        {
            T result = action();
            return Result<T, SodiumFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            return Result<T, SodiumFailure>.Err(errorMapper(ex));
        }
    }
}