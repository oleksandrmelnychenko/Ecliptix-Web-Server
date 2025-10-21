using System.Buffers;
using System.Security.Cryptography;
using Ecliptix.Utilities;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.NativeResolver;

namespace Ecliptix.Security.Certificate.Pinning.Services;

public sealed class CertificatePinningService : IDisposable
{
    private readonly Lock _lock = new();
    private volatile bool _isInitialized;
    private volatile bool _disposed;

    public Result<Unit, CertificatePinningFailure> Initialize()
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return Result<Unit, CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());
            }

            if (_isInitialized)
            {
                return Result<Unit, CertificatePinningFailure>.Ok(Unit.Value);
            }

            try
            {
                int result = CertificatePinningNativeLibrary.Initialize();

                if (result != 0)
                {
                    string error = GetErrorString();
                    return Result<Unit, CertificatePinningFailure>.Err(
                        CertificatePinningFailure.LibraryInitializationFailed(error));
                }

                _isInitialized = true;
                return Result<Unit, CertificatePinningFailure>.Ok(Unit.Value);
            }
            catch (Exception ex)
            {
                return Result<Unit, CertificatePinningFailure>.Err(
                    CertificatePinningFailure.InitializationException(ex));
            }
        }
    }

    public Result<byte[], CertificatePinningFailure> Encrypt(ReadOnlyMemory<byte> plaintext)
    {
        if (_disposed)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());
        }

        if (!_isInitialized)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());
        }

        if (plaintext.Length == 0)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.PlaintextRequired());
        }

        byte[] ciphertext = ArrayPool<byte>.Shared.Rent(CertificatePinningConfigurationConstants.MaxCiphertextSize);
        try
        {
            unsafe
            {
                nuint ciphertextLen = (nuint)ciphertext.Length;
                ReadOnlySpan<byte> plaintextSpan = plaintext.Span;

                fixed (byte* plaintextPtr = plaintextSpan)
                fixed (byte* ciphertextPtr = ciphertext)
                {
                    int encryptResult = CertificatePinningNativeLibrary.Encrypt(
                        plaintextPtr, (nuint)plaintextSpan.Length,
                        ciphertextPtr, &ciphertextLen);

                    if (encryptResult != 0)
                    {
                        string error = GetErrorString();
                        return Result<byte[], CertificatePinningFailure>.Err(
                            CertificatePinningFailure.EncryptionFailed(error));
                    }
                }

                byte[] resultArray = new byte[ciphertextLen];
                ciphertext.AsSpan(0, (int)ciphertextLen).CopyTo(resultArray);
                return Result<byte[], CertificatePinningFailure>.Ok(resultArray);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.EncryptionException(ex));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(ciphertext, clearArray: true);
        }
    }

    public Result<byte[], CertificatePinningFailure> Decrypt(ReadOnlyMemory<byte> ciphertext)
    {
        if (_disposed)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());
        }

        if (!_isInitialized)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());
        }

        if (ciphertext.Length == 0)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.CiphertextRequired());
        }

        byte[] plaintext = ArrayPool<byte>.Shared.Rent(CertificatePinningConfigurationConstants.MaxPlaintextSize);
        nuint actualPlaintextLen = 0;
        try
        {
            unsafe
            {
                nuint plaintextLen = (nuint)plaintext.Length;
                ReadOnlySpan<byte> ciphertextSpan = ciphertext.Span;

                fixed (byte* ciphertextPtr = ciphertextSpan)
                fixed (byte* plaintextPtr = plaintext)
                {
                    int decryptResult = CertificatePinningNativeLibrary.Decrypt(
                        ciphertextPtr, (nuint)ciphertextSpan.Length,
                        plaintextPtr, &plaintextLen);

                    if (decryptResult != 0)
                    {
                        string error = GetErrorString();
                        return Result<byte[], CertificatePinningFailure>.Err(
                            CertificatePinningFailure.DecryptionFailed(error));
                    }

                    actualPlaintextLen = plaintextLen;
                }

                if (actualPlaintextLen > int.MaxValue)
                {
                    return Result<byte[], CertificatePinningFailure>.Err(
                        CertificatePinningFailure.DecryptionFailed("Plaintext too large"));
                }

                byte[] resultArray = new byte[actualPlaintextLen];
                plaintext.AsSpan(0, (int)actualPlaintextLen).CopyTo(resultArray);
                return Result<byte[], CertificatePinningFailure>.Ok(resultArray);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.DecryptionException(ex));
        }
        finally
        {
            if (actualPlaintextLen is > 0 and <= int.MaxValue)
            {
                CryptographicOperations.ZeroMemory(plaintext.AsSpan(0, (int)actualPlaintextLen));
            }

            ArrayPool<byte>.Shared.Return(plaintext, clearArray: true);
        }
    }

    public Result<(byte[], byte[]), CertificatePinningFailure> GenerateEd25519Keypair()
    {
        return GenerateEd25519KeypairSync();
    }

    public Result<byte[], CertificatePinningFailure> SignEd25519(ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> privateKey)
    {
        return SignEd25519Sync(message, privateKey);
    }

    public Result<bool, CertificatePinningFailure> VerifyEd25519(ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKey)
    {
        return VerifyEd25519Sync(message, signature, publicKey);
    }

    public Result<byte[], CertificatePinningFailure> Sign(ReadOnlyMemory<byte> data)
    {
        if (_disposed)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());
        }

        if (!_isInitialized)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());
        }

        if (data.Length == 0)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.DataRequired());
        }

        byte[] signature = ArrayPool<byte>.Shared.Rent(CertificatePinningConfigurationConstants.MaxSignatureSize);
        try
        {
            unsafe
            {
                ReadOnlySpan<byte> dataSpan = data.Span;

                fixed (byte* dataPtr = dataSpan)
                fixed (byte* signaturePtr = signature)
                {
                    nuint signatureLen = (nuint)signature.Length;
                    int result = CertificatePinningNativeLibrary.Sign(
                        dataPtr, (nuint)dataSpan.Length,
                        signaturePtr, &signatureLen);

                    if (result != 0)
                    {
                        string error = GetErrorString();
                        return Result<byte[], CertificatePinningFailure>.Err(
                            CertificatePinningFailure.SigningFailed(error));
                    }

                    if (signatureLen > int.MaxValue)
                    {
                        return Result<byte[], CertificatePinningFailure>.Err(
                            CertificatePinningFailure.SigningFailed("Signature too large"));
                    }

                    byte[] resultArray = new byte[signatureLen];
                    signature.AsSpan(0, (int)signatureLen).CopyTo(resultArray);
                    return Result<byte[], CertificatePinningFailure>.Ok(resultArray);
                }
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.SigningException(ex));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(signature, clearArray: true);
        }
    }

    private Result<(byte[], byte[]), CertificatePinningFailure> GenerateEd25519KeypairSync()
    {
        if (_disposed)
        {
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());
        }

        if (!_isInitialized)
        {
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(CertificatePinningFailure
                .ServiceNotInitialized());
        }

        try
        {
            unsafe
            {
                Span<byte> publicKeySpan =
                    stackalloc byte[CertificatePinningConfigurationConstants.Ed25519PublicKeySize];
                Span<byte> privateKeySpan =
                    stackalloc byte[CertificatePinningConfigurationConstants.Ed25519PrivateKeySize];

                fixed (byte* publicKeyPtr = publicKeySpan)
                fixed (byte* privateKeyPtr = privateKeySpan)
                {
                    CertificatePinningResult result = CertificatePinningNativeLibrary.GenerateEd25519Keypair(
                        publicKeyPtr, privateKeyPtr);

                    if (result != CertificatePinningResult.Success)
                    {
                        string error = GetErrorString();
                        return Result<(byte[], byte[]), CertificatePinningFailure>.Err(
                            CertificatePinningFailure.KeyGenerationFailed(error));
                    }
                }

                byte[] publicKey = publicKeySpan.ToArray();
                byte[] privateKey = privateKeySpan.ToArray();

                CryptographicOperations.ZeroMemory(privateKeySpan);

                return Result<(byte[], byte[]), CertificatePinningFailure>.Ok((publicKey, privateKey));
            }
        }
        catch (Exception ex)
        {
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(CertificatePinningFailure
                .KeyGenerationException(ex));
        }
    }

    private Result<byte[], CertificatePinningFailure> SignEd25519Sync(ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> privateKey)
    {
        if (_disposed)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());
        }

        if (!_isInitialized)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());
        }

        Result<Unit, CertificatePinningFailure> messageValidation = Ed25519Validation.ValidateMessage(message);
        if (messageValidation.IsErr)
        {
            return messageValidation.MapErr(err => err).Map(_ => Array.Empty<byte>());
        }

        Result<Unit, CertificatePinningFailure> privateKeyValidation = Ed25519Validation.ValidatePrivateKey(privateKey);
        if (privateKeyValidation.IsErr)
        {
            return privateKeyValidation.MapErr(err => err).Map(_ => Array.Empty<byte>());
        }

        try
        {
            unsafe
            {
                Span<byte> signatureSpan =
                    stackalloc byte[CertificatePinningConfigurationConstants.Ed25519SignatureSize];
                ReadOnlySpan<byte> messageSpan = message.Span;
                ReadOnlySpan<byte> privateKeySpan = privateKey.Span;

                fixed (byte* messagePtr = messageSpan)
                fixed (byte* privateKeyPtr = privateKeySpan)
                fixed (byte* signaturePtr = signatureSpan)
                {
                    CertificatePinningResult result = CertificatePinningNativeLibrary.SignEd25519(
                        messagePtr, (nuint)messageSpan.Length,
                        privateKeyPtr,
                        signaturePtr);

                    if (result != CertificatePinningResult.Success)
                    {
                        string error = GetErrorString();
                        return Result<byte[], CertificatePinningFailure>.Err(
                            CertificatePinningFailure.SigningFailed(error));
                    }
                }

                return Result<byte[], CertificatePinningFailure>.Ok(signatureSpan.ToArray());
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.SigningException(ex));
        }
    }

    private Result<bool, CertificatePinningFailure> VerifyEd25519Sync(ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKey)
    {
        if (_disposed)
        {
            return Result<bool, CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());
        }

        if (!_isInitialized)
        {
            return Result<bool, CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());
        }

        Result<Unit, CertificatePinningFailure> messageValidation = Ed25519Validation.ValidateMessage(message);
        if (messageValidation.IsErr)
        {
            return messageValidation.MapErr(err => err).Map(_ => false);
        }

        Result<Unit, CertificatePinningFailure> signatureValidation = Ed25519Validation.ValidateSignature(signature);
        if (signatureValidation.IsErr)
        {
            return signatureValidation.MapErr(err => err).Map(_ => false);
        }

        Result<Unit, CertificatePinningFailure> publicKeyValidation = Ed25519Validation.ValidatePublicKey(publicKey);
        if (publicKeyValidation.IsErr)
        {
            return publicKeyValidation.MapErr(err => err).Map(_ => false);
        }

        try
        {
            unsafe
            {
                ReadOnlySpan<byte> messageSpan = message.Span;
                ReadOnlySpan<byte> signatureSpan = signature.Span;
                ReadOnlySpan<byte> publicKeySpan = publicKey.Span;

                fixed (byte* messagePtr = messageSpan)
                fixed (byte* signaturePtr = signatureSpan)
                fixed (byte* publicKeyPtr = publicKeySpan)
                {
                    CertificatePinningResult result = CertificatePinningNativeLibrary.VerifyEd25519(
                        messagePtr, (nuint)messageSpan.Length,
                        signaturePtr,
                        publicKeyPtr);

                    return result switch
                    {
                        CertificatePinningResult.Success => Result<bool, CertificatePinningFailure>.Ok(true),
                        CertificatePinningResult.VerificationFailed =>
                            Result<bool, CertificatePinningFailure>.Ok(false),
                        _ => Result<bool, CertificatePinningFailure>.Err(
                            CertificatePinningFailure.VerificationException(
                                new InvalidOperationException($"Verification internal error: {result}")))
                    };
                }
            }
        }
        catch (Exception ex)
        {
            return Result<bool, CertificatePinningFailure>.Err(CertificatePinningFailure.VerificationException(ex));
        }
    }

    private static unsafe string GetErrorString()
    {
        try
        {
            byte* errorPtr = CertificatePinningNativeLibrary.GetErrorMessage();
            if (errorPtr != null)
            {
                return GetSafeNativeErrorString(errorPtr);
            }
        }
        catch (Exception ex)
        {
            return $"Error retrieving native error message: {ex.Message}";
        }

        return "Error occurred";
    }

    private static unsafe string GetSafeNativeErrorString(byte* errorPtr)
    {
        try
        {
            int length = 0;
            const int maxLength = 4096;

            while (length < maxLength && errorPtr[length] != 0)
            {
                length++;
            }

            return length switch
            {
                0 => "Empty error message",
                maxLength => "Error message too long or not null-terminated",
                _ => System.Text.Encoding.UTF8.GetString(errorPtr, length)
            };
        }
        catch (Exception ex)
        {
            return $"Failed to decode error message: {ex.Message}";
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            try
            {
                if (_isInitialized)
                {
                    CertificatePinningNativeLibrary.Cleanup();
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                _isInitialized = false;
            }
        }
    }

    private static class Ed25519Validation
    {
        private const int PublicKeySize = 32;
        private const int PrivateKeySize = 32;
        private const int SignatureSize = 64;
        private const int MaxMessageSize = 1024 * 1024;

        public static Result<Unit, CertificatePinningFailure> ValidatePublicKey(ReadOnlyMemory<byte> publicKey)
        {
            return publicKey.Length != PublicKeySize
                ? Result<Unit, CertificatePinningFailure>.Err(CertificatePinningFailure.InvalidPublicKey())
                : Result<Unit, CertificatePinningFailure>.Ok(Unit.Value);
        }

        public static Result<Unit, CertificatePinningFailure> ValidatePrivateKey(ReadOnlyMemory<byte> privateKey)
        {
            return privateKey.Length != PrivateKeySize
                ? Result<Unit, CertificatePinningFailure>.Err(CertificatePinningFailure.InvalidPrivateKey())
                : Result<Unit, CertificatePinningFailure>.Ok(Unit.Value);
        }

        public static Result<Unit, CertificatePinningFailure> ValidateSignature(ReadOnlyMemory<byte> signature)
        {
            return signature.Length != SignatureSize
                ? Result<Unit, CertificatePinningFailure>.Err(CertificatePinningFailure.InvalidSignature())
                : Result<Unit, CertificatePinningFailure>.Ok(Unit.Value);
        }

        public static Result<Unit, CertificatePinningFailure> ValidateMessage(ReadOnlyMemory<byte> message)
        {
            return message.Length is 0 or > MaxMessageSize
                ? Result<Unit, CertificatePinningFailure>.Err(CertificatePinningFailure.MessageRequired())
                : Result<Unit, CertificatePinningFailure>.Ok(Unit.Value);
        }
    }
}
