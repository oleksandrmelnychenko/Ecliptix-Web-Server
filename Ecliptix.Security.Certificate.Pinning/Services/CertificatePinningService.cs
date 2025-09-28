using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Ecliptix.Utilities;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.NativeResolver;

namespace Ecliptix.Security.Certificate.Pinning.Services;

public sealed class CertificatePinningService : IDisposable
{
    private volatile bool _isInitialized;
    private volatile bool _disposed;

    public ValueTask<Result<Unit, CertificatePinningFailure>> InitializeAsync()
    {
        return ValueTask.FromResult(InitializeSync());
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

    public ValueTask<Result<byte[], CertificatePinningFailure>> EncryptAsync(ReadOnlyMemory<byte> plaintext)
    {
        return ValueTask.FromResult(EncryptSync(plaintext));
    }

    private Result<byte[], CertificatePinningFailure> EncryptSync(ReadOnlyMemory<byte> plaintext)
    {
        if (!_isInitialized)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());

        if (plaintext.Length == 0)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.PlaintextRequired());

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
                        return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.EncryptionFailed(error));
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

    public ValueTask<Result<byte[], CertificatePinningFailure>> DecryptAsync(ReadOnlyMemory<byte> ciphertext)
    {
        return ValueTask.FromResult(DecryptSync(ciphertext));
    }

    private Result<byte[], CertificatePinningFailure> DecryptSync(ReadOnlyMemory<byte> ciphertext)
    {
        if (!_isInitialized)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());

        if (ciphertext.Length == 0)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.CiphertextRequired());

        byte[] plaintext = ArrayPool<byte>.Shared.Rent(CertificatePinningConfigurationConstants.MaxPlaintextSize);
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
                        return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.DecryptionFailed(error));
                    }
                }

                byte[] resultArray = new byte[plaintextLen];
                plaintext.AsSpan(0, (int)plaintextLen).CopyTo(resultArray);
                return Result<byte[], CertificatePinningFailure>.Ok(resultArray);
            }
        }
        catch (Exception ex)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.DecryptionException(ex));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext.AsSpan(0, CertificatePinningConfigurationConstants.MaxPlaintextSize));
            ArrayPool<byte>.Shared.Return(plaintext, clearArray: false);
        }
    }

    public ValueTask<Result<(byte[], byte[]), CertificatePinningFailure>> GenerateEd25519KeypairAsync()
    {
        return ValueTask.FromResult(GenerateEd25519KeypairSync());
    }

    public ValueTask<Result<byte[], CertificatePinningFailure>> SignEd25519Async(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> privateKey)
    {
        return ValueTask.FromResult(SignEd25519Sync(message, privateKey));
    }

    public ValueTask<Result<bool, CertificatePinningFailure>> VerifyEd25519Async(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKey)
    {
        return ValueTask.FromResult(VerifyEd25519Sync(message, signature, publicKey));
    }

    public ValueTask<Result<byte[], CertificatePinningFailure>> SignAsync(ReadOnlyMemory<byte> data)
    {
        return ValueTask.FromResult(SignSync(data));
    }

    private Result<byte[], CertificatePinningFailure> SignSync(ReadOnlyMemory<byte> data)
    {
        if (!_isInitialized)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());

        if (data.Length == 0)
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.DataRequired());

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
                        return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.SigningFailed(error));
                    }

                    byte[] result_array = new byte[signatureLen];
                    signature.AsSpan(0, (int)signatureLen).CopyTo(result_array);
                    return Result<byte[], CertificatePinningFailure>.Ok(result_array);
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
        if (!_isInitialized)
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceNotInitialized());

        if (_disposed)
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(CertificatePinningFailure.ServiceDisposed());

        try
        {
            unsafe
            {
                Span<byte> publicKeySpan = stackalloc byte[CertificatePinningConfigurationConstants.Ed25519PublicKeySize];
                Span<byte> privateKeySpan = stackalloc byte[CertificatePinningConfigurationConstants.Ed25519PrivateKeySize];

                fixed (byte* publicKeyPtr = publicKeySpan)
                fixed (byte* privateKeyPtr = privateKeySpan)
                {
                    CertificatePinningResult result = CertificatePinningNativeLibrary.GenerateEd25519Keypair(
                        publicKeyPtr, privateKeyPtr);

                    if (result != CertificatePinningResult.Success)
                    {
                        string error = GetErrorString();
                        return Result<(byte[], byte[]), CertificatePinningFailure>.Err(CertificatePinningFailure.KeyGenerationFailed(error));
                    }
                }

                byte[] publicKey = publicKeySpan.ToArray();
                byte[] privateKey = privateKeySpan.ToArray();
                return Result<(byte[], byte[]), CertificatePinningFailure>.Ok((publicKey, privateKey));
            }
        }
        catch (Exception ex)
        {
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(CertificatePinningFailure.KeyGenerationException(ex));
        }
    }

    private Result<byte[], CertificatePinningFailure> SignEd25519Sync(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> privateKey)
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
                Span<byte> signatureSpan = stackalloc byte[CertificatePinningConfigurationConstants.Ed25519SignatureSize];
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
                        return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.SigningFailed(error));
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

    private Result<bool, CertificatePinningFailure> VerifyEd25519Sync(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKey)
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