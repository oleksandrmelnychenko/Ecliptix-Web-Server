using System.Buffers;
using System.Security.Cryptography;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.NativeResolver;
using Ecliptix.SharedKernel;

namespace Ecliptix.Security.Certificate.Pinning.Services;

public sealed class CertificatePinningService : IDisposable
{
    private readonly object _stateLock = new();
    private volatile bool _isInitialized;
    private volatile bool _disposed;
    private volatile bool _disposing;
    private int _activeOperations;

    public Result<Unit, CertificatePinningFailure> Initialize()
    {
        lock (_stateLock)
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

    public unsafe Result<Unit, CertificatePinningFailure> InitializeWithKeys(
        ReadOnlySpan<byte> rsaPrivateKeyDer,
        ReadOnlySpan<byte> ed25519PrivateKey)
    {
        lock (_stateLock)
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
                fixed (byte* rsaKeyPtr = rsaPrivateKeyDer)
                fixed (byte* ed25519KeyPtr = ed25519PrivateKey)
                {
                    int result = CertificatePinningNativeLibrary.InitializeWithKeys(
                        rsaKeyPtr, (nuint)rsaPrivateKeyDer.Length,
                        ed25519KeyPtr, (nuint)ed25519PrivateKey.Length);

                    if (result != 0)
                    {
                        string error = GetErrorString();
                        return Result<Unit, CertificatePinningFailure>.Err(
                            CertificatePinningFailure.LibraryInitializationFailed(error));
                    }
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
        if (plaintext.Length == 0)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.PlaintextRequired());
        }

        if (!TryEnterOperation(out CertificatePinningFailure? enterError))
        {
            return Result<byte[], CertificatePinningFailure>.Err(enterError!);
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
            ExitOperation();
        }
    }

    public Result<byte[], CertificatePinningFailure> Decrypt(ReadOnlyMemory<byte> ciphertext)
    {
        if (ciphertext.Length == 0)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.CiphertextRequired());
        }

        if (!TryEnterOperation(out CertificatePinningFailure? enterError))
        {
            return Result<byte[], CertificatePinningFailure>.Err(enterError!);
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
            CryptographicOperations.ZeroMemory(plaintext.AsSpan(0, (int)actualPlaintextLen));

            ArrayPool<byte>.Shared.Return(plaintext, clearArray: true);
            ExitOperation();
        }
    }

    public Result<byte[], CertificatePinningFailure> Sign(ReadOnlyMemory<byte> data)
    {
        if (data.Length == 0)
        {
            return Result<byte[], CertificatePinningFailure>.Err(CertificatePinningFailure.DataRequired());
        }

        if (!TryEnterOperation(out CertificatePinningFailure? enterError))
        {
            return Result<byte[], CertificatePinningFailure>.Err(enterError!);
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
            ExitOperation();
        }
    }

    public Result<(byte[] PublicKey, byte[] PrivateKey), CertificatePinningFailure> GenerateRsaKeypair()
    {
        if (!TryEnterOperation(out CertificatePinningFailure? enterError))
        {
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(enterError!);
        }

        byte[] privateKeyDer = ArrayPool<byte>.Shared.Rent(CertificatePinningConfigurationConstants.RsaPrivateKeyDerMaxSize);
        byte[] publicKeyDer = ArrayPool<byte>.Shared.Rent(CertificatePinningConfigurationConstants.RsaPublicKeyDerSize);

        try
        {
            unsafe
            {
                nuint privateKeyLen = (nuint)privateKeyDer.Length;
                nuint publicKeyLen = (nuint)publicKeyDer.Length;

                fixed (byte* privateKeyPtr = privateKeyDer)
                fixed (byte* publicKeyPtr = publicKeyDer)
                {
                    int result = CertificatePinningNativeLibrary.GenerateRsaKeypair(
                        privateKeyPtr, &privateKeyLen,
                        publicKeyPtr, &publicKeyLen);

                    if (result != 0)
                    {
                        string error = GetErrorString();
                        return Result<(byte[], byte[]), CertificatePinningFailure>.Err(
                            CertificatePinningFailure.KeyGenerationFailed(error));
                    }

                    byte[] privateKey = privateKeyDer.AsSpan(0, (int)privateKeyLen).ToArray();
                    byte[] publicKey = publicKeyDer.AsSpan(0, (int)publicKeyLen).ToArray();

                    return Result<(byte[], byte[]), CertificatePinningFailure>.Ok((publicKey, privateKey));
                }
            }
        }
        catch (Exception ex)
        {
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(
                CertificatePinningFailure.KeyGenerationException(ex));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKeyDer);
            ArrayPool<byte>.Shared.Return(privateKeyDer, clearArray: true);
            ArrayPool<byte>.Shared.Return(publicKeyDer, clearArray: true);
            ExitOperation();
        }
    }

    public Result<(byte[] PublicKey, byte[] PrivateKey), CertificatePinningFailure> GenerateEd25519Keypair()
    {
        if (!TryEnterOperation(out CertificatePinningFailure? enterError))
        {
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(enterError!);
        }

        try
        {
            unsafe
            {
                Span<byte> publicKeySpan = stackalloc byte[CertificatePinningConfigurationConstants.Ed25519PublicKeySize];
                Span<byte> privateKeySpan = stackalloc byte[CertificatePinningConfigurationConstants.Ed25519PrivateKeySize];
                nuint publicKeyLen = (nuint)publicKeySpan.Length;
                nuint privateKeyLen = (nuint)privateKeySpan.Length;

                fixed (byte* publicKeyPtr = publicKeySpan)
                fixed (byte* privateKeyPtr = privateKeySpan)
                {
                    int result = CertificatePinningNativeLibrary.GenerateEd25519Keypair(
                        privateKeyPtr, &privateKeyLen,
                        publicKeyPtr, &publicKeyLen);

                    if (result != 0)
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
            return Result<(byte[], byte[]), CertificatePinningFailure>.Err(
                CertificatePinningFailure.KeyGenerationException(ex));
        }
        finally
        {
            ExitOperation();
        }
    }

    public static unsafe void SecureWipe(Span<byte> data)
    {
        fixed (byte* dataPtr = data)
        {
            CertificatePinningNativeLibrary.SecureWipe(dataPtr, (nuint)data.Length);
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

        return CertificatePinningConfigurationConstants.ErrorMessages.GenericError;
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
        lock (_stateLock)
        {
            if (_disposed)
            {
                return;
            }

            _disposing = true;

            try
            {
                while (_activeOperations > 0)
                {
                    Monitor.Wait(_stateLock);
                }

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
                _disposed = true;
                _disposing = false;
            }
        }
    }

    private bool TryEnterOperation(out CertificatePinningFailure? error)
    {
        lock (_stateLock)
        {
            if (_disposed || _disposing)
            {
                error = CertificatePinningFailure.ServiceDisposed();
                return false;
            }

            if (!_isInitialized)
            {
                error = CertificatePinningFailure.ServiceNotInitialized();
                return false;
            }

            _activeOperations++;
            error = null;
            return true;
        }
    }

    private void ExitOperation()
    {
        lock (_stateLock)
        {
            _activeOperations--;
            Monitor.PulseAll(_stateLock);
        }
    }
}
