namespace Ecliptix.Utilities.Failures.Sodium;

public enum SodiumFailureType
{
    InitializationFailed,
    LibraryNotFound,
    AllocationFailed,
    MemoryPinningFailed,
    SecureWipeFailed,
    InvalidBufferSize,
    BufferTooSmall,
    BufferTooLarge,
    NullPointer,
    MemoryProtectionFailed,
    ComparisonFailed
}