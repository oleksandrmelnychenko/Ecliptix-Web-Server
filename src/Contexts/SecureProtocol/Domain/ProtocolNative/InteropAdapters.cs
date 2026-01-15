using System.Runtime.InteropServices;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.SharedKernel;
using Native = Ecliptix.SecureProtocol.Domain.ProtocolNative.NativeInterop;

namespace Ecliptix.SecureProtocol.Domain.ProtocolNative;

public sealed class EcliptixIdentityKeys : IDisposable
{
    private IntPtr _handle;
    private bool _ownsHandle = true;
    private bool _disposed;

    private EcliptixIdentityKeys(IntPtr handle)
    {
        _handle = handle;
    }

    public bool IsDisposed => _disposed;
    internal IntPtr Handle => _handle;

    public static Result<EcliptixIdentityKeys, EcliptixProtocolFailure> Create()
    {
        Native.EppErrorCode result = Native.epp_identity_create(
            out IntPtr handle,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        if (handle == IntPtr.Zero)
        {
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration("Identity keys creation returned null handle despite success status"));
        }

        return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Ok(new EcliptixIdentityKeys(handle));
    }

    public static Result<EcliptixIdentityKeys, EcliptixProtocolFailure> CreateFromSeed(byte[] seed, string? context = null)
    {
        if (context is null)
        {
            return CreateFromSeed(seed);
        }

        Native.EppErrorCode result = Native.epp_identity_create_with_context(
            seed,
            (nuint)seed.Length,
            context,
            (nuint)context.Length,
            out IntPtr handle,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        if (handle == IntPtr.Zero)
        {
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration("Identity keys creation returned null handle despite success status"));
        }

        return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Ok(new EcliptixIdentityKeys(handle));
    }

    public static Result<EcliptixIdentityKeys, EcliptixProtocolFailure> CreateFromSeed(byte[] seed)
    {
        Console.WriteLine($"[IDENTITY-CREATE] Creating identity from seed, seed length: {seed.Length}");

        Native.EppErrorCode result = Native.epp_identity_create_from_seed(
            seed,
            (nuint)seed.Length,
            out IntPtr handle,
            out Native.EppError error);

        Console.WriteLine($"[IDENTITY-CREATE] Native call returned: {result}, handle: 0x{handle:X}");

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Console.WriteLine($"[IDENTITY-CREATE] Failed: {message}");
            Native.epp_error_free(ref error);
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("[IDENTITY-CREATE] ERROR: Success but null handle!");
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration("Identity keys creation returned null handle despite success status"));
        }

        Console.WriteLine($"[IDENTITY-CREATE] Success! Handle: 0x{handle:X}");
        return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Ok(new EcliptixIdentityKeys(handle));
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicX25519()
    {
        ThrowIfDisposed();

        if (_handle == IntPtr.Zero)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration("Identity keys handle is zero (not disposed but invalid)"));
        }

        byte[] publicKey = new byte[32];
        Native.EppErrorCode result = Native.epp_identity_get_x25519_public(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicEd25519()
    {
        ThrowIfDisposed();

        if (_handle == IntPtr.Zero)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration("Identity keys handle is zero (not disposed but invalid)"));
        }

        byte[] publicKey = new byte[32];
        Native.EppErrorCode result = Native.epp_identity_get_ed25519_public(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicKyber()
    {
        Console.WriteLine($"[GET-KYBER] GetPublicKyber called, disposed: {_disposed}, handle: 0x{_handle:X}");
        ThrowIfDisposed();

        if (_handle == IntPtr.Zero)
        {
            Console.WriteLine("[GET-KYBER] ERROR: Handle is zero!");
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration("Identity keys handle is zero (not disposed but invalid)"));
        }

        byte[] publicKey = new byte[1184]; // ML-KEM-768 public key size
        Console.WriteLine($"[GET-KYBER] Calling native epp_identity_get_kyber_public with handle 0x{_handle:X}");

        Native.EppErrorCode result = Native.epp_identity_get_kyber_public(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out Native.EppError error);

        Console.WriteLine($"[GET-KYBER] Native call returned: {result}");

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Console.WriteLine($"[GET-KYBER] Failed: {message}");
            Native.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        Console.WriteLine($"[GET-KYBER] Success! Key length: {publicKey.Length}");
        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    internal void Detach()
    {
        if (_disposed)
        {
            return;
        }

        _ownsHandle = false;
        _handle = IntPtr.Zero;
        _disposed = true;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_ownsHandle && _handle != IntPtr.Zero)
        {
            Native.epp_identity_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcliptixIdentityKeys));
        }
    }
}

public sealed class EcliptixProtocolSystem : IDisposable
{
    private IntPtr _handle;
    private readonly EcliptixIdentityKeys _identityKeys;
    private bool _disposed;
    private GCHandle _callbackHandle;
    private Native.EppCallbacks _callbacks;

    private EcliptixProtocolSystem(IntPtr handle, EcliptixIdentityKeys identityKeys)
    {
        _handle = handle;
        _identityKeys = identityKeys;
    }

    public bool IsDisposed => _disposed;

    public static Result<EcliptixProtocolSystem, EcliptixProtocolFailure> Create(EcliptixIdentityKeys identityKeys)
    {
        Native.EppErrorCode result = Native.epp_server_create(
            identityKeys.Handle,
            out IntPtr handle,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Ok(
            new EcliptixProtocolSystem(handle, identityKeys));
    }

    public static Result<EcliptixProtocolSystem, EcliptixProtocolFailure> CreateFromRoot(
        EcliptixIdentityKeys identityKeys,
        byte[] rootKey,
        byte[] peerBundle,
        bool isInitiator)
    {
        Native.EppErrorCode result = Native.epp_server_create_from_root(
            identityKeys.Handle,
            rootKey,
            (nuint)rootKey.Length,
            peerBundle,
            (nuint)peerBundle.Length,
            isInitiator,
            out IntPtr handle,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Ok(
            new EcliptixProtocolSystem(handle, identityKeys));
    }

    public static Result<EcliptixProtocolSystem, EcliptixProtocolFailure> ImportState(
        EcliptixIdentityKeys identityKeys,
        byte[] stateBytes)
    {
        Native.EppErrorCode result = Native.epp_server_deserialize(
            identityKeys.Handle,
            stateBytes,
            (nuint)stateBytes.Length,
            out IntPtr handle,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Ok(
            new EcliptixProtocolSystem(handle, identityKeys));
    }

    public Result<Unit, EcliptixProtocolFailure> SetEventHandler(Action<uint>? onProtocolStateChanged)
    {
        ThrowIfDisposed();

        if (_callbackHandle.IsAllocated)
        {
            _callbackHandle.Free();
        }

        if (onProtocolStateChanged != null)
        {
            Native.EppEventCallback callback = (connectionId, _) => onProtocolStateChanged(connectionId);
            _callbackHandle = GCHandle.Alloc(callback);

            _callbacks = new Native.EppCallbacks
            {
                OnProtocolStateChanged = callback,
                UserData = IntPtr.Zero
            };

            Native.EppErrorCode result = Native.epp_server_set_callbacks(
                _handle,
                in _callbacks,
                out Native.EppError error);

            if (result != Native.EppErrorCode.Success)
            {
                string message = error.GetMessage();
                Native.epp_error_free(ref error);
                _callbackHandle.Free();
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Failed to set callbacks: {message}"));
            }
        }
        else
        {
            _callbacks = new Native.EppCallbacks
            {
                OnProtocolStateChanged = null,
                UserData = IntPtr.Zero
            };

            Native.epp_server_set_callbacks(
                _handle,
                in _callbacks,
                out _);
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public Result<byte[], EcliptixProtocolFailure> BeginHandshake(
        uint connectionId,
        PubKeyExchangeType exchangeType,
        byte[] peerKyberPublicKey)
    {
        ThrowIfDisposed();

        IntPtr bufferPtr = Native.epp_buffer_alloc(0);
        Native.EppErrorCode result = Native.epp_server_begin_handshake(
            _handle,
            connectionId,
            (byte)exchangeType,
            peerKyberPublicKey,
            (nuint)peerKyberPublicKey.Length,
            bufferPtr,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            Native.epp_buffer_free(bufferPtr);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return CopyAndFree(bufferPtr);
    }

    public Result<Unit, EcliptixProtocolFailure> CompleteHandshake(byte[] peerHandshakeMessage, byte[] rootKey)
    {
        ThrowIfDisposed();

        Native.EppErrorCode result = Native.epp_server_complete_handshake(
            _handle,
            peerHandshakeMessage,
            (nuint)peerHandshakeMessage.Length,
            rootKey,
            (nuint)rootKey.Length,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public Result<Unit, EcliptixProtocolFailure> CompleteHandshakeAuto(byte[] peerHandshakeMessage)
    {
        ThrowIfDisposed();

        Native.EppErrorCode result = Native.epp_server_complete_handshake_auto(
            _handle,
            peerHandshakeMessage,
            (nuint)peerHandshakeMessage.Length,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public Result<byte[], EcliptixProtocolFailure> SendMessage(byte[] plaintext)
    {
        ThrowIfDisposed();

        IntPtr bufferPtr = Native.epp_buffer_alloc(0);
        Native.EppErrorCode result = Native.epp_server_encrypt(
            _handle,
            plaintext,
            (nuint)plaintext.Length,
            bufferPtr,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            Native.epp_buffer_free(bufferPtr);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return CopyAndFree(bufferPtr);
    }

    public Result<byte[], EcliptixProtocolFailure> ReceiveMessage(byte[] encryptedEnvelope)
    {
        ThrowIfDisposed();

        IntPtr bufferPtr = Native.epp_buffer_alloc(0);
        Native.EppErrorCode result = Native.epp_server_decrypt(
            _handle,
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            bufferPtr,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            Native.epp_buffer_free(bufferPtr);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return CopyAndFree(bufferPtr);
    }

    public Result<bool, EcliptixProtocolFailure> HasConnection()
    {
        ThrowIfDisposed();

        Native.EppErrorCode result = Native.epp_server_is_established(
            _handle,
            out bool hasConnection,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<bool, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<bool, EcliptixProtocolFailure>.Ok(hasConnection);
    }

    public Result<uint, EcliptixProtocolFailure> GetConnectionId()
    {
        ThrowIfDisposed();

        Native.EppErrorCode result = Native.epp_server_get_id(
            _handle,
            out uint connectionId,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<uint, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<uint, EcliptixProtocolFailure>.Ok(connectionId);
    }

    public Result<uint?, EcliptixProtocolFailure> GetSelectedOpkId()
    {
        ThrowIfDisposed();

        Native.EppErrorCode result = Native.epp_server_get_used_prekey_id(
            _handle,
            out bool hasOpkId,
            out uint opkId,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<uint?, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<uint?, EcliptixProtocolFailure>.Ok(hasOpkId ? opkId : null);
    }

    public Result<byte[], EcliptixProtocolFailure> ExportState()
    {
        ThrowIfDisposed();

        IntPtr bufferPtr = Native.epp_buffer_alloc(0);
        Native.EppErrorCode result = Native.epp_server_serialize(
            _handle,
            bufferPtr,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return CopyAndFree(bufferPtr);
    }

    public Result<ulong, EcliptixProtocolFailure> GetSessionAgeSeconds()
    {
        ThrowIfDisposed();

        Native.EppErrorCode result = Native.epp_session_age_seconds(
            _handle,
            out ulong ageSeconds,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<ulong, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<ulong, EcliptixProtocolFailure>.Ok(ageSeconds);
    }

    public Result<Unit, EcliptixProtocolFailure> SetKyberSecrets(byte[] kyberCiphertext, byte[] kyberSharedSecret)
    {
        ThrowIfDisposed();

        Native.EppErrorCode result = Native.epp_server_set_kyber_secrets(
            _handle,
            kyberCiphertext,
            (nuint)kyberCiphertext.Length,
            kyberSharedSecret,
            (nuint)kyberSharedSecret.Length,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public static Result<Unit, EcliptixProtocolFailure> ValidateEnvelopeHybridRequirements(byte[] encryptedEnvelope)
    {
        Native.EppErrorCode result = Native.epp_envelope_validate(
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public static Result<byte[], EcliptixProtocolFailure> DeriveRootFromOpaqueSessionKey(
        byte[] opaqueSessionKey,
        byte[] userContext)
    {
        byte[] rootKey = new byte[32];
        Native.EppErrorCode result = Native.epp_derive_root_key(
            opaqueSessionKey,
            (nuint)opaqueSessionKey.Length,
            userContext,
            (nuint)userContext.Length,
            rootKey,
            (nuint)rootKey.Length,
            out Native.EppError error);

        if (result != Native.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(rootKey);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_callbackHandle.IsAllocated)
        {
            _callbackHandle.Free();
        }

        if (_handle != IntPtr.Zero)
        {
            Native.epp_server_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private static Result<byte[], EcliptixProtocolFailure> CopyAndFree(IntPtr bufferPtr)
    {
        try
        {
            Native.EppBuffer buffer = Marshal.PtrToStructure<Native.EppBuffer>(bufferPtr);
            byte[] data = new byte[buffer.Length];
            Marshal.Copy(buffer.Data, data, 0, (int)buffer.Length);
            return Result<byte[], EcliptixProtocolFailure>.Ok(data);
        }
        finally
        {
            if (bufferPtr != IntPtr.Zero)
            {
                Native.epp_buffer_free(bufferPtr);
            }
        }
    }

    private static EcliptixProtocolFailure ConvertError(Native.EppErrorCode code, string message) =>
        code switch
        {
            Native.EppErrorCode.ErrorInvalidInput => EcliptixProtocolFailure.InvalidInput(message),
            Native.EppErrorCode.ErrorKeyGeneration => EcliptixProtocolFailure.KeyGeneration(message),
            Native.EppErrorCode.ErrorDeriveKey => EcliptixProtocolFailure.DeriveKey(message),
            Native.EppErrorCode.ErrorHandshake => EcliptixProtocolFailure.Handshake(message),
            Native.EppErrorCode.ErrorDecode => EcliptixProtocolFailure.Decode(message),
            Native.EppErrorCode.ErrorEncode => EcliptixProtocolFailure.Decode(message),
            Native.EppErrorCode.ErrorBufferTooSmall => EcliptixProtocolFailure.BufferTooSmall(message),
            Native.EppErrorCode.ErrorEncryption => EcliptixProtocolFailure.SessionAuthFailed(message),
            Native.EppErrorCode.ErrorDecryption => EcliptixProtocolFailure.SessionAuthFailed(message),
            Native.EppErrorCode.ErrorObjectDisposed => EcliptixProtocolFailure.ObjectDisposed(message),
            Native.EppErrorCode.ErrorPrepareLocal => EcliptixProtocolFailure.PrepareLocal(message),
            Native.EppErrorCode.ErrorReplayAttack => EcliptixProtocolFailure.ReplayAttempt(message),
            Native.EppErrorCode.ErrorSessionExpired => EcliptixProtocolFailure.SessionAuthFailed(message),
            Native.EppErrorCode.ErrorOutOfMemory => EcliptixProtocolFailure.Generic(message),
            Native.EppErrorCode.ErrorNullPointer => EcliptixProtocolFailure.InvalidInput(message),
            Native.EppErrorCode.ErrorInvalidState => EcliptixProtocolFailure.InvalidInput(message),
            Native.EppErrorCode.ErrorPqMissing => EcliptixProtocolFailure.Decode(message),
            _ => EcliptixProtocolFailure.Generic(message)
        };

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcliptixProtocolSystem));
        }
    }
}
