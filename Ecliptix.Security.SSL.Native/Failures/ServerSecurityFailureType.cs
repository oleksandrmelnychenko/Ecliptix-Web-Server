/*
 * Ecliptix Security SSL Native Library
 * Author: Oleksandr Melnychenko
 */

namespace Ecliptix.Security.SSL.Native.Failures;

public enum ServerSecurityFailureType
{
    ServiceNotInitialized,
    ServiceDisposed,
    LibraryInitializationFailed,
    InitializationException,
    PlaintextRequired,
    PlaintextTooLarge,
    PublicKeyRequired,
    RsaEncryptionFailed,
    RsaEncryptionException,
    CiphertextRequired,
    RsaDecryptionFailed,
    RsaDecryptionException,
    MessageRequired,
    Ed25519SigningFailed,
    Ed25519SigningException,
    PrivateKeyLoadFailed,
    KeyLoadException,
    LibraryCleanupError
}