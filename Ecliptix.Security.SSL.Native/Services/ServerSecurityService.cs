using System.Runtime.InteropServices;
using System.Text;
using Ecliptix.Domain.Utilities;
using Ecliptix.Security.SSL.Native.Native;
using Ecliptix.Security.SSL.Native.Failures;

namespace Ecliptix.Security.SSL.Native.Services;

public sealed class ServerSecurityService : IDisposable
{
    private volatile bool _isInitialized;
    private volatile bool _disposed;

    public ServerSecurityService()
    {
    }

    public Task<Result<Unit, ServerSecurityFailure>> InitializeAsync()
    {
        return Task.Run(InitializeSync);
    }

    public Task<Result<Unit, ServerSecurityFailure>> InitializeWithKeyAsync(string privateKeyPem)
    {
        return Task.Run(() => InitializeWithKeySync(privateKeyPem));
    }

    public Task<Result<Unit, ServerSecurityFailure>> InitializeWithKeysAsync(string serverPrivateKeyPem, string clientPublicKeyPem)
    {
        return Task.Run(() => InitializeWithKeysSync(serverPrivateKeyPem, clientPublicKeyPem));
    }

    private Result<Unit, ServerSecurityFailure> InitializeSync()
    {
        if (_disposed)
            return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        if (_isInitialized)
            return Result<Unit, ServerSecurityFailure>.Ok(Unit.Value);

        try
        {
            int result = EcliptixServerNativeLibrary.Initialize();

            if (result != 0)
            {
                string error = GetErrorString();
                return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.LibraryInitializationFailed(error));
            }

            _isInitialized = true;
            return Result<Unit, ServerSecurityFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.InitializationException(ex));
        }
    }

    private Result<Unit, ServerSecurityFailure> InitializeWithKeySync(string privateKeyPem)
    {
        if (_disposed)
            return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        if (_isInitialized)
            return Result<Unit, ServerSecurityFailure>.Ok(Unit.Value);

        if (string.IsNullOrEmpty(privateKeyPem))
            return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.PrivateKeyRequired());

        try
        {
            unsafe
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(privateKeyPem);

                fixed (byte* keyPtr = keyBytes)
                {
                    int result = EcliptixServerNativeLibrary.InitializeWithKey(keyPtr, (nuint)keyBytes.Length);

                    if (result != 0)
                    {
                        string error = GetErrorString();
                        return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.LibraryInitializationFailed(error));
                    }
                }
            }

            _isInitialized = true;
            return Result<Unit, ServerSecurityFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.InitializationException(ex));
        }
    }

    private Result<Unit, ServerSecurityFailure> InitializeWithKeysSync(string serverPrivateKeyPem, string clientPublicKeyPem)
    {
        if (_disposed)
            return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        if (_isInitialized)
            return Result<Unit, ServerSecurityFailure>.Ok(Unit.Value);

        if (string.IsNullOrEmpty(serverPrivateKeyPem))
            return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.PrivateKeyRequired());

        if (string.IsNullOrEmpty(clientPublicKeyPem))
            return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.PublicKeyRequired());

        try
        {
            unsafe
            {
                byte[] serverKeyBytes = Encoding.UTF8.GetBytes(serverPrivateKeyPem);
                byte[] clientKeyBytes = Encoding.UTF8.GetBytes(clientPublicKeyPem);

                fixed (byte* serverKeyPtr = serverKeyBytes)
                fixed (byte* clientKeyPtr = clientKeyBytes)
                {
                    int result = EcliptixServerNativeLibrary.InitializeWithKeys(
                        serverKeyPtr, (nuint)serverKeyBytes.Length,
                        clientKeyPtr, (nuint)clientKeyBytes.Length);

                    if (result != 0)
                    {
                        string error = GetErrorString();
                        return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.LibraryInitializationFailed(error));
                    }
                }
            }

            _isInitialized = true;
            return Result<Unit, ServerSecurityFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.InitializationException(ex));
        }
    }

    public Task<Result<byte[], ServerSecurityFailure>> EncryptAsync(byte[] plaintext)
    {
        return Task.Run(() => EncryptSync(plaintext));
    }

    private Result<byte[], ServerSecurityFailure> EncryptSync(byte[] plaintext)
    {
        if (!_isInitialized)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        if (plaintext.Length == 0)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.PlaintextRequired());

        try
        {
            unsafe
            {
                byte[] ciphertext = new byte[EcliptixServerConstants.MaxCiphertextSize];
                nuint ciphertextLen = (nuint)ciphertext.Length;

                fixed (byte* plaintextPtr = plaintext)
                fixed (byte* ciphertextPtr = ciphertext)
                {
                    int result = EcliptixServerNativeLibrary.Encrypt(
                        plaintextPtr, (nuint)plaintext.Length,
                        ciphertextPtr, &ciphertextLen);

                    if (result != 0)
                    {
                        string error = GetErrorString();
                        return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.EncryptionFailed(error));
                    }
                }

                Array.Resize(ref ciphertext, (int)ciphertextLen);
                return Result<byte[], ServerSecurityFailure>.Ok(ciphertext);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.EncryptionException(ex));
        }
    }

    public Task<Result<byte[], ServerSecurityFailure>> DecryptAsync(byte[] ciphertext)
    {
        return Task.Run(() => DecryptSync(ciphertext));
    }

    private Result<byte[], ServerSecurityFailure> DecryptSync(byte[] ciphertext)
    {
        if (!_isInitialized)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        if (ciphertext.Length == 0)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.CiphertextRequired());

        try
        {
            unsafe
            {
                byte[] plaintext = new byte[EcliptixServerConstants.MaxPlaintextSize];
                nuint plaintextLen = (nuint)plaintext.Length;

                fixed (byte* ciphertextPtr = ciphertext)
                fixed (byte* plaintextPtr = plaintext)
                {
                    int result = EcliptixServerNativeLibrary.Decrypt(
                        ciphertextPtr, (nuint)ciphertext.Length,
                        plaintextPtr, &plaintextLen);

                    if (result != 0)
                    {
                        string error = GetErrorString();
                        return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.DecryptionFailed(error));
                    }
                }

                Array.Resize(ref plaintext, (int)plaintextLen);
                return Result<byte[], ServerSecurityFailure>.Ok(plaintext);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.DecryptionException(ex));
        }
    }

    public Task<Result<(byte[], byte[]), ServerSecurityFailure>> GenerateEd25519KeypairAsync()
    {
        return Task.Run(GenerateEd25519KeypairSync);
    }

    public Task<Result<byte[], ServerSecurityFailure>> SignEd25519Async(byte[] message, byte[] privateKey)
    {
        return Task.Run(() => SignEd25519Sync(message, privateKey));
    }

    public Task<Result<bool, ServerSecurityFailure>> VerifyEd25519Async(byte[] message, byte[] signature, byte[] publicKey)
    {
        return Task.Run(() => VerifyEd25519Sync(message, signature, publicKey));
    }

    public Task<Result<byte[], ServerSecurityFailure>> SignAsync(byte[] data)
    {
        return Task.Run(() => SignSync(data));
    }

    private Result<byte[], ServerSecurityFailure> SignSync(byte[] data)
    {
        if (!_isInitialized)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        if (data.Length == 0)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.DataRequired());

        try
        {
            unsafe
            {
                byte[] signature = new byte[EcliptixServerConstants.MaxSignatureSize];

                fixed (byte* dataPtr = data)
                fixed (byte* signaturePtr = signature)
                {
                    nuint signatureLen = (nuint)signature.Length; 
                    int result = EcliptixServerNativeLibrary.Sign(
                        dataPtr, (nuint)data.Length,
                        signaturePtr, &signatureLen);

                    if (result != 0)
                    {
                        string error = GetErrorString();
                        return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.SigningFailed(error));
                    }

                    Array.Resize(ref signature, (int)signatureLen);
                }

                return Result<byte[], ServerSecurityFailure>.Ok(signature);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.SigningException(ex));
        }
    }

    private Result<(byte[], byte[]), ServerSecurityFailure> GenerateEd25519KeypairSync()
    {
        if (!_isInitialized)
            return Result<(byte[], byte[]), ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<(byte[], byte[]), ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        try
        {
            unsafe
            {
                byte[] publicKey = new byte[EcliptixServerConstants.Ed25519PublicKeySize];
                byte[] privateKey = new byte[EcliptixServerConstants.Ed25519PrivateKeySize];

                fixed (byte* publicKeyPtr = publicKey)
                fixed (byte* privateKeyPtr = privateKey)
                {
                    EcliptixServerResult result = EcliptixServerNativeLibrary.GenerateEd25519Keypair(
                        publicKeyPtr, privateKeyPtr);

                    if (result != EcliptixServerResult.Success)
                    {
                        string error = GetErrorString();
                        return Result<(byte[], byte[]), ServerSecurityFailure>.Err(ServerSecurityFailure.KeyGenerationFailed(error));
                    }
                }

                return Result<(byte[], byte[]), ServerSecurityFailure>.Ok((publicKey, privateKey));
            }
        }
        catch (Exception ex)
        {
            return Result<(byte[], byte[]), ServerSecurityFailure>.Err(ServerSecurityFailure.KeyGenerationException(ex));
        }
    }

    private Result<byte[], ServerSecurityFailure> SignEd25519Sync(byte[] message, byte[] privateKey)
    {
        if (!_isInitialized)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        if (message.Length == 0)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.MessageRequired());

        if (privateKey.Length != EcliptixServerConstants.Ed25519PrivateKeySize)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.InvalidPrivateKey());

        try
        {
            unsafe
            {
                byte[] signature = new byte[EcliptixServerConstants.Ed25519SignatureSize];

                fixed (byte* messagePtr = message)
                fixed (byte* privateKeyPtr = privateKey)
                fixed (byte* signaturePtr = signature)
                {
                    EcliptixServerResult result = EcliptixServerNativeLibrary.SignEd25519(
                        messagePtr, (nuint)message.Length,
                        privateKeyPtr,
                        signaturePtr);

                    if (result != EcliptixServerResult.Success)
                    {
                        string error = GetErrorString();
                        return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.SigningFailed(error));
                    }
                }

                return Result<byte[], ServerSecurityFailure>.Ok(signature);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.SigningException(ex));
        }
    }

    private Result<bool, ServerSecurityFailure> VerifyEd25519Sync(byte[] message, byte[] signature, byte[] publicKey)
    {
        if (!_isInitialized)
            return Result<bool, ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<bool, ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        if (message.Length == 0)
            return Result<bool, ServerSecurityFailure>.Err(ServerSecurityFailure.MessageRequired());

        if (signature.Length != EcliptixServerConstants.Ed25519SignatureSize)
            return Result<bool, ServerSecurityFailure>.Err(ServerSecurityFailure.InvalidSignature());

        if (publicKey.Length != EcliptixServerConstants.Ed25519PublicKeySize)
            return Result<bool, ServerSecurityFailure>.Err(ServerSecurityFailure.InvalidPublicKey());

        try
        {
            unsafe
            {
                fixed (byte* messagePtr = message)
                fixed (byte* signaturePtr = signature)
                fixed (byte* publicKeyPtr = publicKey)
                {
                    EcliptixServerResult result = EcliptixServerNativeLibrary.VerifyEd25519(
                        messagePtr, (nuint)message.Length,
                        signaturePtr,
                        publicKeyPtr);

                    return result == EcliptixServerResult.Success
                        ? Result<bool, ServerSecurityFailure>.Ok(true)
                        : Result<bool, ServerSecurityFailure>.Ok(false);
                }
            }
        }
        catch (Exception ex)
        {
            return Result<bool, ServerSecurityFailure>.Err(ServerSecurityFailure.VerificationException(ex));
        }
    }

    private static unsafe string GetErrorString()
    {
        try
        {
            byte* errorPtr = EcliptixServerNativeLibrary.GetErrorMessage();
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
                EcliptixServerNativeLibrary.Cleanup();
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