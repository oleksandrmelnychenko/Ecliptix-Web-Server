namespace Ecliptix.Utilities.Failures.Sodium;

public static class SodiumFailureMessages
{
    public const string SodiumInitFailed = "sodium_init() returned an error code.";

    public const string LibraryLoadFailed =
        "Failed to load {0}. Ensure the native library is available and compatible.";

    public const string InitializationFailed = "Failed to initialize libsodium library.";
    public const string UnexpectedInitError = "An unexpected error occurred during libsodium initialization.";
    public const string NotInitialized = "SodiumInterop is not initialized. Cannot perform secure wipe.";
    public const string BufferNull = "Buffer cannot be null.";
    public const string BufferTooLarge = "Buffer size ({0:N0} bytes) exceeds maximum ({1:N0} bytes).";
    public const string SmallBufferClearFailed = "Failed to clear small buffer ({0} bytes) using Array.Clear.";
    public const string PinningFailed = "Failed to pin buffer memory (GCHandle.Alloc). Invalid buffer or handle type.";
    public const string InsufficientMemory = "Insufficient memory to pin buffer (GCHandle.Alloc).";

    public const string AddressOfPinnedObjectFailed =
        "GCHandle.Alloc succeeded, but AddrOfPinnedObject returned IntPtr.Zero for a non-empty buffer.";

    public const string GetPinnedAddressFailed = "Failed to get address of pinned buffer.";
    public const string SecureWipeFailed = "Unexpected error during secure wipe via sodium_memzero ({0} bytes).";

    public const string NegativeAllocationLength = "Requested allocation length cannot be negative ({0}).";
    public const string SodiumNotInitialized = "SodiumInterop is not initialized.";
    public const string AllocationFailed = "sodium_malloc failed to allocate {0} bytes.";
    public const string UnexpectedAllocationError = "Unexpected error during allocation ({0} bytes).";
    public const string ObjectDisposed = "Cannot access disposed resource '{0}'.";
    public const string DataTooLarge = "Data length ({0}) exceeds allocated buffer size ({1}).";
    public const string ReferenceCountFailed = "Failed to increment reference count.";
    public const string DisposedAfterAddRef = "{0} disposed after AddRef.";
    public const string UnexpectedWriteError = "Unexpected error during write operation.";
    public const string BufferTooSmall = "Destination buffer size ({0}) is smaller than the allocated size ({1}).";
    public const string UnexpectedReadError = "Unexpected error during read operation.";
    public const string NegativeReadLength = "Requested read length cannot be negative ({0}).";
    public const string ReadLengthExceedsSize = "Requested read length ({0}) exceeds allocated size ({1}).";
    public const string UnexpectedReadBytesError = "Unexpected error reading {0} bytes.";
}