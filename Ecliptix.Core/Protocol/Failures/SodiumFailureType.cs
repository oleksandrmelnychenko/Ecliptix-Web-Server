namespace Ecliptix.Core.Protocol.Failures;

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