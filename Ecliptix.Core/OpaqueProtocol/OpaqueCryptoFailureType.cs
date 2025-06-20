namespace Ecliptix.Core.OpaqueProtocol;

public enum OpaqueCryptoFailureType
{
    HashingValidPointFailed,
    AeadDecryptFailed,
    AeadEncryptFailed,
    InvalidInput,
    OprfHashingFailed,
    InvalidKeySignature,
}