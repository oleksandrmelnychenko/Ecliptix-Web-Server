namespace Ecliptix.Core.Infrastructure.Crypto;

public enum RsaPaddingMode
{
    Oaep,
    Pkcs1
}

public interface IRsaConfiguration
{
    int KeySize { get; }
    int EncryptedBlockSize { get; }
    int MaxPlaintextSize { get; }
    int OptimalChunkSize { get; }
    RsaPaddingMode PaddingMode { get; }
}