using System.Runtime.InteropServices;
using Ecliptix.Domain.Utilities;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.NativeResolver;

namespace Ecliptix.Security.Certificate.Pinning.Services;

public sealed class EcliptixCertificatePinningService : IDisposable
{
    private volatile bool _isInitialized;
    private volatile bool _disposed;

    public Task<Result<Unit, CertificatePinningFailure>> InitializeAsync()
    {
        return Task.Run(InitializeSync);
    }

    private Result<Unit, CertificatePinningFailure> InitializeSync()
    {
        if (_disposed)
            return Result<Unit, CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());

        if (_isInitialized)
            return Result<Unit, CertificatePinningFailure>.Ok(Unit.Value);

        try
        {
            int result = CertificatePinningNativeLibrary.Initialize();

            if (result != 0)
            {
                string error = GetErrorString();
                return Result<Unit, CertificatePinningFailure>.Err(CertificatePinningFailure.LibraryInitializationFailed(error));
            }

            _isInitialized = true;
            return Result<Unit, CertificatePinningFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, CertificatePinningFailure>.Err(CertificatePinningFailure.InitializationException(ex));
        }
    }

    public Task<Result<byte[], CertificatePinningFailure>> EncryptAsync(byte[] plaintext)
    {
        return Task.Run(() => EncryptSync(plaintext));
    }

    private Result<byte[], CertificatePinningFailure> EncryptSync(byte[] plaintext)
    {
        if (!_isInitialized)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());

        if (plaintext.Length == 0)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.PlaintextRequired());

        try
        {
            unsafe
            {
                byte[] ciphertext = new byte[CertificatePinningConfigurationConstants.MaxCiphertextSize];
                nuint ciphertextLen = (nuint)ciphertext.Length;

                fixed (byte* plaintextPtr = plaintext)
                fixed (byte* ciphertextPtr = ciphertext)
                {
                    int result = CertificatePinningNativeLibrary.Encrypt(
                        plaintextPtr, (nuint)plaintext.Length,
                        ciphertextPtr, &ciphertextLen);

                    if (result != 0)
                    {
                        string error = GetErrorString();
                        return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.EncryptionFailed(error));
                    }
                }

                Array.Resize(ref ciphertext, (int)ciphertextLen);
                return Result<byte[], CertificatePinningFailure>.Ok(ciphertext);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.EncryptionException(ex));
        }
    }

    public Task<Result<byte[], CertificatePinningFailure>> DecryptAsync(byte[] ciphertext)
    {
        return Task.Run(() => DecryptSync(ciphertext));
    }

    private Result<byte[], CertificatePinningFailure> DecryptSync(byte[] ciphertext)
    {
        if (!_isInitialized)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());

        if (ciphertext.Length == 0)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.CiphertextRequired());

        try
        {
            unsafe
            {
                byte[] plaintext = new byte[CertificatePinningConfigurationConstants.MaxPlaintextSize];
                nuint plaintextLen = (nuint)plaintext.Length;

                fixed (byte* ciphertextPtr = ciphertext)
                fixed (byte* plaintextPtr = plaintext)
                {
                    int result = CertificatePinningNativeLibrary.Decrypt(
                        ciphertextPtr, (nuint)ciphertext.Length,
                        plaintextPtr, &plaintextLen);

                    if (result != 0)
                    {
                        string error = GetErrorString();
                        return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.DecryptionFailed(error));
                    }
                }

                Array.Resize(ref plaintext, (int)plaintextLen);
                return Result<byte[], CertificatePinningFailure>.Ok(plaintext);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.DecryptionException(ex));
        }
    }

    public Task<Result<(byte[], byte[]), CertificatePinningFailure>> GenerateEd25519KeypairAsync()
    {
        return Task.Run(GenerateEd25519KeypairSync);
    }

    public Task<Result<byte[], CertificatePinningFailure>> SignEd25519Async(byte[] message, byte[] privateKey)
    {
        return Task.Run(() => SignEd25519Sync(message, privateKey));
    }

    public Task<Result<bool, CertificatePinningFailure>> VerifyEd25519Async(byte[] message, byte[] signature, byte[] publicKey)
    {
        return Task.Run(() => VerifyEd25519Sync(message, signature, publicKey));
    }

    public Task<Result<byte[], CertificatePinningFailure>> SignAsync(byte[] data)
    {
        return Task.Run(() => SignSync(data));
    }

    private Result<byte[], CertificatePinningFailure> SignSync(byte[] data)
    {
        if (!_isInitialized)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());

        if (data.Length == 0)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.DataRequired());

        try
        {
            unsafe
            {
                byte[] signature = new byte[CertificatePinningConfigurationConstants.MaxSignatureSize];

                fixed (byte* dataPtr = data)
                fixed (byte* signaturePtr = signature)
                {
                    nuint signatureLen = (nuint)signature.Length; 
                    int result = CertificatePinningNativeLibrary.Sign(
                        dataPtr, (nuint)data.Length,
                        signaturePtr, &signatureLen);

                    if (result != 0)
                    {
                        string error = GetErrorString();
                        return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.SigningFailed(error));
                    }

                    Array.Resize(ref signature, (int)signatureLen);
                }

                return Result<byte[], CertificatePinningFailure>.Ok(signature);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.SigningException(ex));
        }
    }

    private Result<(byte[], byte[]), CertificatePinningFailure> GenerateEd25519KeypairSync()
    {
        if (!_isInitialized)
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());

        try
        {
            unsafe
            {
                byte[] publicKey = new byte[CertificatePinningConfigurationConstants.Ed25519PublicKeySize];
                byte[] privateKey = new byte[CertificatePinningConfigurationConstants.Ed25519PrivateKeySize];

                fixed (byte* publicKeyPtr = publicKey)
                fixed (byte* privateKeyPtr = privateKey)
                {
                    CertificatePinningResult result = CertificatePinningNativeLibrary.GenerateEd25519Keypair(
                        publicKeyPtr, privateKeyPtr);

                    if (result != CertificatePinningResult.Success)
                    {
                        string error = GetErrorString();
                        return Result<(byte[], byte[]), CertificatePinningFailure>.Err(CertificatePinningFailure.KeyGenerationFailed(error));
                    }
                }

                return Result<(byte[], byte[]), CertificatePinningFailure>.Ok((publicKey, privateKey));
            }
        }
        catch (Exception ex)
        {
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(CertificatePinningFailure.KeyGenerationException(ex));
        }
    }

    private Result<byte[], CertificatePinningFailure> SignEd25519Sync(byte[] message, byte[] privateKey)
    {
        if (!_isInitialized)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());

        if (message.Length == 0)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.MessageRequired());

        if (privateKey.Length != CertificatePinningConfigurationConstants.Ed25519PrivateKeySize)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.InvalidPrivateKey());

        try
        {
            unsafe
            {
                byte[] signature = new byte[CertificatePinningConfigurationConstants.Ed25519SignatureSize];

                fixed (byte* messagePtr = message)
                fixed (byte* privateKeyPtr = privateKey)
                fixed (byte* signaturePtr = signature)
                {
                    CertificatePinningResult result = CertificatePinningNativeLibrary.SignEd25519(
                        messagePtr, (nuint)message.Length,
                        privateKeyPtr,
                        signaturePtr);

                    if (result != CertificatePinningResult.Success)
                    {
                        string error = GetErrorString();
                        return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.SigningFailed(error));
                    }
                }

                return Result<byte[], CertificatePinningFailure>.Ok(signature);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.SigningException(ex));
        }
    }

    private Result<bool, CertificatePinningFailure> VerifyEd25519Sync(byte[] message, byte[] signature, byte[] publicKey)
    {
        if (!_isInitialized)
            return Result<bool, CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<bool, CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());

        if (message.Length == 0)
            return Result<bool, CertificatePinningFailure>.Err(CertificatePinningFailure.MessageRequired());

        if (signature.Length != CertificatePinningConfigurationConstants.Ed25519SignatureSize)
            return Result<bool, CertificatePinningFailure>.Err(CertificatePinningFailure.InvalidSignature());

        if (publicKey.Length != CertificatePinningConfigurationConstants.Ed25519PublicKeySize)
            return Result<bool, CertificatePinningFailure>.Err(CertificatePinningFailure.InvalidPublicKey());

        try
        {
            unsafe
            {
                fixed (byte* messagePtr = message)
                fixed (byte* signaturePtr = signature)
                fixed (byte* publicKeyPtr = publicKey)
                {
                    CertificatePinningResult result = CertificatePinningNativeLibrary.VerifyEd25519(
                        messagePtr, (nuint)message.Length,
                        signaturePtr,
                        publicKeyPtr);

                    return result == CertificatePinningResult.Success
                        ? Result<bool, CertificatePinningFailure>.Ok(true)
                        : Result<bool, CertificatePinningFailure>.Ok(false);
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
                return Marshal.PtrToStringUTF8((IntPtr)errorPtr) ?? "Unknown error";
            }
        }
        catch
        {
            // ignored
        }

        return "Error occurred";
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        try
        {
            if (_isInitialized)
            {
                CertificatePinningNativeLibrary.Cleanup();
            }
        }
        catch (Exception)
        {
            // ignored
        }
        finally
        {
            _disposed = true;
            _isInitialized = false;
        }
    }
}