namespace Ecliptix.Core.OpaqueProtocol;

public class OpaqueFailure
{
    private OpaqueFailure(OpaqueCryptoFailureType type, string message, Exception? innerException = null)
    {
        Type = type;
        Message = message;
        InnerException = innerException;
    }

    public OpaqueCryptoFailureType Type { get; }
    public string Message { get; }
    public Exception? InnerException { get; }
    
    public static OpaqueFailure InvalidKeySignature(string details, Exception? inner = null)
    {
        return new OpaqueFailure(OpaqueCryptoFailureType.InvalidKeySignature, details, inner);
    }
    
    public static OpaqueFailure HashingValidPointFailed(string details, Exception? inner = null)
    {
        return new OpaqueFailure(OpaqueCryptoFailureType.HashingValidPointFailed, details, inner);
    }
    
    public static OpaqueFailure AeadDecryptFailed(string details, Exception? inner = null)
    {
        return new OpaqueFailure(OpaqueCryptoFailureType.AeadDecryptFailed, details, inner);
    }
    
    public static OpaqueFailure AeadEncryptFailed(string details, Exception? inner = null)
    {
        return new OpaqueFailure(OpaqueCryptoFailureType.AeadEncryptFailed, details, inner);
    }
    
    public static OpaqueFailure InvalidInput(string details, Exception? inner = null)
    {
        return new OpaqueFailure(OpaqueCryptoFailureType.InvalidInput, details, inner);
    }
    
    public static OpaqueFailure OprfHashingFailed(string details, Exception? inner = null)
    {
        return new OpaqueFailure(OpaqueCryptoFailureType.OprfHashingFailed, details, inner);
    }
}