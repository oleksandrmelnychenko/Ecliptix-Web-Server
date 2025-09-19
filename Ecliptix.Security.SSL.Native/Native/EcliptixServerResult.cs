/*
 * Ecliptix Security SSL Native Library
 * Result codes from the Ecliptix server security library
 * Author: Oleksandr Melnychenko
 */

namespace Ecliptix.Security.SSL.Native.Native;

public enum EcliptixServerResult
{
    Success = 0,
    ErrorNotInitialized = -1,
    ErrorInvalidParam = -3,
    ErrorMemoryAllocation = -4,
    ErrorCryptoFailure = -5,
    ErrorKeyLoadFailed = -6,
    ErrorSignatureFailed = -11,
    ErrorDecryptionFailed = -12,
    ErrorEncryptionFailed = -13,
    ErrorBufferTooSmall = -14,
    ErrorUnknown = -99
}