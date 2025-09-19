/*
 * Ecliptix Security SSL Native Library
 * Server-side security service providing RSA encryption/decryption and Ed25519 digital signatures
 * Author: Oleksandr Melnychenko
 */

using System.Runtime.InteropServices;
using System.Text;
using Ecliptix.Security.SSL.Native.Native;
using Ecliptix.Security.SSL.Native.Resources;
using Ecliptix.Security.SSL.Native.Failures;
using Ecliptix.Security.SSL.Native.Common;

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

    private Result<Unit, ServerSecurityFailure> InitializeSync()
    {
        if (_disposed)
            return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        if (_isInitialized)
            return Result<Unit, ServerSecurityFailure>.Ok(Unit.Value);

        try
        {
            unsafe
            {
                SavePrivateKeysToTempLocation();

                EcliptixServerResult result = EcliptixServerNativeLibrary.Initialize();

                if (result != EcliptixServerResult.Success)
                {
                    string error = GetErrorString(result);
                    return Result<Unit, ServerSecurityFailure>.Err(ServerSecurityFailure.LibraryInitializationFailed(error));
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

    private void SavePrivateKeysToTempLocation()
    {
        string tempKeysDir = "/Users/oleksandrmelnychenko/RiderProjects/Ecliptix/server-keys";
        Directory.CreateDirectory(tempKeysDir);

        var ed25519Key = EmbeddedResourceLoader.LoadEd25519PrivateKey();
        var rsaKey = EmbeddedResourceLoader.LoadRsaServerPrivateKey();

        File.WriteAllText(Path.Combine(tempKeysDir, "ecliptix_ed25519_private.pem"), ed25519Key);
        File.WriteAllText(Path.Combine(tempKeysDir, "ecliptix_server_private.pem"), rsaKey);
    }

    public Task<Result<byte[], ServerSecurityFailure>> EncryptRsaAsync(byte[] plaintext, byte[] publicKeyPem)
    {
        return Task.Run(() => EncryptRsaSync(plaintext, publicKeyPem));
    }

    private Result<byte[], ServerSecurityFailure> EncryptRsaSync(byte[] plaintext, byte[] publicKeyPem)
    {
        if (!_isInitialized)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        if (plaintext == null || plaintext.Length == 0)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.PlaintextRequired());

        if (publicKeyPem == null || publicKeyPem.Length == 0)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.PublicKeyRequired());

        const int maxPlaintextSize = EcliptixServerConstants.RsaMaxPlaintextSize;
        if (plaintext.Length > maxPlaintextSize)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.PlaintextTooLarge());

        try
        {
            unsafe
            {
                const int rsaKeySize = EcliptixServerConstants.RsaCiphertextSize;
                byte[] ciphertext = new byte[rsaKeySize];
                nuint ciphertextSize = (nuint)rsaKeySize;

                fixed (byte* plaintextPtr = plaintext)
                fixed (byte* publicKeyPtr = publicKeyPem)
                fixed (byte* ciphertextPtr = ciphertext)
                {
                    EcliptixServerResult result = EcliptixServerNativeLibrary.EncryptRSA(
                        plaintextPtr, (nuint)plaintext.Length,
                        publicKeyPtr, (nuint)publicKeyPem.Length,
                        ciphertextPtr, &ciphertextSize);

                    if (result != EcliptixServerResult.Success)
                    {
                        string error = GetErrorString(result);
                        return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.RsaEncryptionFailed(error));
                    }
                }

                Array.Resize(ref ciphertext, (int)ciphertextSize);
                return Result<byte[], ServerSecurityFailure>.Ok(ciphertext);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.RsaEncryptionException(ex));
        }
    }

    public Task<Result<byte[], ServerSecurityFailure>> DecryptRsaAsync(byte[] ciphertext)
    {
        return Task.Run(() => DecryptRsaSync(ciphertext));
    }

    private Result<byte[], ServerSecurityFailure> DecryptRsaSync(byte[] ciphertext)
    {
        if (!_isInitialized)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        if (ciphertext == null || ciphertext.Length == 0)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.CiphertextRequired());

        try
        {
            unsafe
            {
                const int maxPlaintextSize = EcliptixServerConstants.RsaMaxPlaintextSize;
                byte[] plaintext = new byte[maxPlaintextSize];
                nuint plaintextSize = (nuint)maxPlaintextSize;

                fixed (byte* ciphertextPtr = ciphertext)
                fixed (byte* plaintextPtr = plaintext)
                {
                    EcliptixServerResult result = EcliptixServerNativeLibrary.DecryptRSA(
                        ciphertextPtr, (nuint)ciphertext.Length,
                        plaintextPtr, &plaintextSize);

                    if (result != EcliptixServerResult.Success)
                    {
                        string error = GetErrorString(result);
                        return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.RsaDecryptionFailed(error));
                    }
                }

                Array.Resize(ref plaintext, (int)plaintextSize);
                return Result<byte[], ServerSecurityFailure>.Ok(plaintext);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.RsaDecryptionException(ex));
        }
    }

    public Task<Result<byte[], ServerSecurityFailure>> SignEd25519Async(byte[] message)
    {
        return Task.Run(() => SignEd25519Sync(message));
    }

    private Result<byte[], ServerSecurityFailure> SignEd25519Sync(byte[] message)
    {
        if (!_isInitialized)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.ServiceDisposed());

        if (message == null || message.Length == 0)
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.MessageRequired());

        try
        {
            unsafe
            {
                byte[] signature = new byte[EcliptixServerConstants.Ed25519SignatureSize];

                fixed (byte* messagePtr = message)
                fixed (byte* sigPtr = signature)
                {
                    EcliptixServerResult result = EcliptixServerNativeLibrary.SignEd25519(
                        messagePtr, (nuint)message.Length, sigPtr);

                    if (result != EcliptixServerResult.Success)
                    {
                        string error = GetErrorString(result);
                        return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.Ed25519SigningFailed(error));
                    }
                }

                return Result<byte[], ServerSecurityFailure>.Ok(signature);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], ServerSecurityFailure>.Err(ServerSecurityFailure.Ed25519SigningException(ex));
        }
    }

    private unsafe string GetErrorString(EcliptixServerResult result)
    {
        try
        {
            byte* errorPtr = EcliptixServerNativeLibrary.GetErrorMessage();
            if (errorPtr != null)
            {
                return Marshal.PtrToStringUTF8((IntPtr)errorPtr) ?? $"Unknown error: {result}";
            }
        }
        catch
        {
        }

        return $"Error code: {result}";
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
        }
        finally
        {
            _disposed = true;
            _isInitialized = false;
        }
    }
}