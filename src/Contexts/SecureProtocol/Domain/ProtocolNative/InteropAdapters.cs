using System.Runtime.InteropServices;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.SharedKernel;
using Native = Ecliptix.SecureProtocol.Domain.ProtocolNative.NativeInterop;

namespace Ecliptix.SecureProtocol.Domain.ProtocolNative;

/// <summary>
/// SharedKernel-friendly wrappers over the native protocol server interop.
/// </summary>
public sealed class EcliptixIdentityKeys : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    private EcliptixIdentityKeys(IntPtr handle)
    {
        _handle = handle;
    }

    public bool IsDisposed => _disposed;
    internal IntPtr Handle => _handle;

    public static Result<EcliptixIdentityKeys, EcliptixProtocolFailure> Create()
    {
        Native.EcliptixErrorCode result = Native.ecliptix_identity_keys_create(
            out IntPtr handle,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Ok(new EcliptixIdentityKeys(handle));
    }

    public static Result<EcliptixIdentityKeys, EcliptixProtocolFailure> CreateFromSeed(byte[] seed, string? context = null)
    {
        if (context is null)
        {
            return CreateFromSeed(seed);
        }

        Native.EcliptixErrorCode result = Native.ecliptix_identity_keys_create_from_seed_with_context(
            seed,
            (nuint)seed.Length,
            context,
            (nuint)context.Length,
            out IntPtr handle,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Ok(new EcliptixIdentityKeys(handle));
    }

    public static Result<EcliptixIdentityKeys, EcliptixProtocolFailure> CreateFromSeed(byte[] seed)
    {
        Native.EcliptixErrorCode result = Native.ecliptix_identity_keys_create_from_seed(
            seed,
            (nuint)seed.Length,
            out IntPtr handle,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Ok(new EcliptixIdentityKeys(handle));
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicX25519()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[32];
        Native.EcliptixErrorCode result = Native.ecliptix_identity_keys_get_public_x25519(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicEd25519()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[32];
        Native.EcliptixErrorCode result = Native.ecliptix_identity_keys_get_public_ed25519(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    /// <summary>
    /// Gets the identity Kyber (ML-KEM-768) public key (1184 bytes).
    /// </summary>
    public Result<byte[], EcliptixProtocolFailure> GetPublicKyber()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[1184]; // ML-KEM-768 public key size
        Native.EcliptixErrorCode result = Native.ecliptix_identity_keys_get_public_kyber(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_handle != IntPtr.Zero)
        {
        Native.ecliptix_identity_keys_destroy(_handle);
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
    private Native.EcliptixCallbacks _callbacks;

    private EcliptixProtocolSystem(IntPtr handle, EcliptixIdentityKeys identityKeys)
    {
        _handle = handle;
        _identityKeys = identityKeys;
    }

    public bool IsDisposed => _disposed;

    public static Result<EcliptixProtocolSystem, EcliptixProtocolFailure> Create(EcliptixIdentityKeys identityKeys)
    {
        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_create(
            identityKeys.Handle,
            out IntPtr handle,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
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
        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_create_from_root(
            identityKeys.Handle,
            rootKey,
            (nuint)rootKey.Length,
            peerBundle,
            (nuint)peerBundle.Length,
            isInitiator,
            out IntPtr handle,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<EcliptixProtocolSystem, EcliptixProtocolFailure>.Ok(
            new EcliptixProtocolSystem(handle, identityKeys));
    }

    public static Result<EcliptixProtocolSystem, EcliptixProtocolFailure> ImportState(
        EcliptixIdentityKeys identityKeys,
        byte[] stateBytes)
    {
        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_import_state(
            identityKeys.Handle,
            stateBytes,
            (nuint)stateBytes.Length,
            out IntPtr handle,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
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
            Native.EcliptixProtocolEventCallback callback = (connectionId, _) => onProtocolStateChanged(connectionId);
            _callbackHandle = GCHandle.Alloc(callback);

            _callbacks = new Native.EcliptixCallbacks
            {
                OnProtocolStateChanged = callback,
                UserData = IntPtr.Zero
            };

            Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_set_callbacks(
                _handle,
                in _callbacks,
                out Native.EcliptixError error);

            if (result != Native.EcliptixErrorCode.Success)
            {
                string message = error.GetMessage();
                Native.ecliptix_error_free(ref error);
                _callbackHandle.Free();
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Failed to set callbacks: {message}"));
            }
        }
        else
        {
            _callbacks = new Native.EcliptixCallbacks
            {
                OnProtocolStateChanged = null,
                UserData = IntPtr.Zero
            };

            Native.ecliptix_protocol_server_system_set_callbacks(
                _handle,
                in _callbacks,
                out _);
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public Result<byte[], EcliptixProtocolFailure> BeginHandshake(uint connectionId, PubKeyExchangeType exchangeType)
    {
        ThrowIfDisposed();

        IntPtr bufferPtr = Native.ecliptix_buffer_allocate(0);
        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_begin_handshake(
            _handle,
            connectionId,
            (byte)exchangeType,
            bufferPtr,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            Native.ecliptix_buffer_free(bufferPtr);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return CopyAndFree(bufferPtr);
    }

    public Result<byte[], EcliptixProtocolFailure> BeginHandshakeWithKyber(
        uint connectionId,
        PubKeyExchangeType exchangeType,
        byte[] peerKyberPublicKey)
    {
        ThrowIfDisposed();

        IntPtr bufferPtr = Native.ecliptix_buffer_allocate(0);
        Native.EcliptixErrorCode result = Native
            .ecliptix_protocol_server_system_begin_handshake_with_peer_kyber(
                _handle,
                connectionId,
                (byte)exchangeType,
                peerKyberPublicKey,
                (nuint)peerKyberPublicKey.Length,
                bufferPtr,
                out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            Native.ecliptix_buffer_free(bufferPtr);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return CopyAndFree(bufferPtr);
    }

    public Result<Unit, EcliptixProtocolFailure> CompleteHandshake(byte[] peerHandshakeMessage, byte[] rootKey)
    {
        ThrowIfDisposed();

        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_complete_handshake(
            _handle,
            peerHandshakeMessage,
            (nuint)peerHandshakeMessage.Length,
            rootKey,
            (nuint)rootKey.Length,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public Result<Unit, EcliptixProtocolFailure> CompleteHandshakeAuto(byte[] peerHandshakeMessage)
    {
        ThrowIfDisposed();

        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_complete_handshake_auto(
            _handle,
            peerHandshakeMessage,
            (nuint)peerHandshakeMessage.Length,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public Result<byte[], EcliptixProtocolFailure> SendMessage(byte[] plaintext)
    {
        ThrowIfDisposed();

        IntPtr bufferPtr = Native.ecliptix_buffer_allocate(0);
        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_send_message(
            _handle,
            plaintext,
            (nuint)plaintext.Length,
            bufferPtr,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            Native.ecliptix_buffer_free(bufferPtr);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return CopyAndFree(bufferPtr);
    }

    public Result<byte[], EcliptixProtocolFailure> ReceiveMessage(byte[] encryptedEnvelope)
    {
        ThrowIfDisposed();

        IntPtr bufferPtr = Native.ecliptix_buffer_allocate(0);
        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_receive_message(
            _handle,
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            bufferPtr,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            Native.ecliptix_buffer_free(bufferPtr);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return CopyAndFree(bufferPtr);
    }

    public Result<bool, EcliptixProtocolFailure> HasConnection()
    {
        ThrowIfDisposed();

        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_has_connection(
            _handle,
            out bool hasConnection,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<bool, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<bool, EcliptixProtocolFailure>.Ok(hasConnection);
    }

    public Result<uint, EcliptixProtocolFailure> GetConnectionId()
    {
        ThrowIfDisposed();

        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_get_connection_id(
            _handle,
            out uint connectionId,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<uint, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<uint, EcliptixProtocolFailure>.Ok(connectionId);
    }

    public Result<uint?, EcliptixProtocolFailure> GetSelectedOpkId()
    {
        ThrowIfDisposed();

        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_get_selected_opk_id(
            _handle,
            out bool hasOpkId,
            out uint opkId,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<uint?, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<uint?, EcliptixProtocolFailure>.Ok(hasOpkId ? opkId : null);
    }

    public Result<byte[], EcliptixProtocolFailure> ExportState()
    {
        ThrowIfDisposed();

        IntPtr bufferPtr = Native.ecliptix_buffer_allocate(0);
        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_export_state(
            _handle,
            bufferPtr,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return CopyAndFree(bufferPtr);
    }

    public Result<ulong, EcliptixProtocolFailure> GetSessionAgeSeconds()
    {
        ThrowIfDisposed();

        Native.EcliptixErrorCode result = Native.ecliptix_connection_get_session_age_seconds(
            _handle,
            out ulong ageSeconds,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<ulong, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<ulong, EcliptixProtocolFailure>.Ok(ageSeconds);
    }

    public Result<Unit, EcliptixProtocolFailure> SetKyberSecrets(byte[] kyberCiphertext, byte[] kyberSharedSecret)
    {
        ThrowIfDisposed();

        Native.EcliptixErrorCode result = Native.ecliptix_protocol_server_system_set_kyber_secrets(
            _handle,
            kyberCiphertext,
            (nuint)kyberCiphertext.Length,
            kyberSharedSecret,
            (nuint)kyberSharedSecret.Length,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public static Result<Unit, EcliptixProtocolFailure> ValidateEnvelopeHybridRequirements(byte[] encryptedEnvelope)
    {
        Native.EcliptixErrorCode result = Native.ecliptix_envelope_validate_hybrid_requirements(
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(ConvertError(result, message));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public static Result<byte[], EcliptixProtocolFailure> DeriveRootFromOpaqueSessionKey(
        byte[] opaqueSessionKey,
        byte[] userContext)
    {
        byte[] rootKey = new byte[32];
        Native.EcliptixErrorCode result = Native.ecliptix_derive_root_from_opaque_session_key(
            opaqueSessionKey,
            (nuint)opaqueSessionKey.Length,
            userContext,
            (nuint)userContext.Length,
            rootKey,
            (nuint)rootKey.Length,
            out Native.EcliptixError error);

        if (result != Native.EcliptixErrorCode.Success)
        {
            string message = error.GetMessage();
            Native.ecliptix_error_free(ref error);
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
            Native.ecliptix_protocol_server_system_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private static Result<byte[], EcliptixProtocolFailure> CopyAndFree(IntPtr bufferPtr)
    {
        try
        {
            Native.EcliptixBuffer buffer = Marshal.PtrToStructure<Native.EcliptixBuffer>(bufferPtr);
            byte[] data = new byte[buffer.Length];
            Marshal.Copy(buffer.Data, data, 0, (int)buffer.Length);
            return Result<byte[], EcliptixProtocolFailure>.Ok(data);
        }
        finally
        {
            if (bufferPtr != IntPtr.Zero)
            {
                Native.ecliptix_buffer_free(bufferPtr);
            }
        }
    }

    private static EcliptixProtocolFailure ConvertError(Native.EcliptixErrorCode code, string message) =>
        code switch
        {
            Native.EcliptixErrorCode.ErrorInvalidInput => EcliptixProtocolFailure.InvalidInput(message),
            Native.EcliptixErrorCode.ErrorKeyGeneration => EcliptixProtocolFailure.KeyGeneration(message),
            Native.EcliptixErrorCode.ErrorDeriveKey => EcliptixProtocolFailure.DeriveKey(message),
            Native.EcliptixErrorCode.ErrorHandshake => EcliptixProtocolFailure.Handshake(message),
            Native.EcliptixErrorCode.ErrorDecode => EcliptixProtocolFailure.Decode(message),
            Native.EcliptixErrorCode.ErrorEncode => EcliptixProtocolFailure.Decode(message),
            Native.EcliptixErrorCode.ErrorBufferTooSmall => EcliptixProtocolFailure.BufferTooSmall(message),
            Native.EcliptixErrorCode.ErrorEncryption => EcliptixProtocolFailure.SessionAuthFailed(message),
            Native.EcliptixErrorCode.ErrorDecryption => EcliptixProtocolFailure.SessionAuthFailed(message),
            Native.EcliptixErrorCode.ErrorObjectDisposed => EcliptixProtocolFailure.ObjectDisposed(message),
            Native.EcliptixErrorCode.ErrorPrepareLocal => EcliptixProtocolFailure.PrepareLocal(message),
            Native.EcliptixErrorCode.ErrorReplayAttack => EcliptixProtocolFailure.ReplayAttempt(message),
            Native.EcliptixErrorCode.ErrorSessionExpired => EcliptixProtocolFailure.SessionAuthFailed(message),
            Native.EcliptixErrorCode.ErrorOutOfMemory => EcliptixProtocolFailure.Generic(message),
            Native.EcliptixErrorCode.ErrorNullPointer => EcliptixProtocolFailure.InvalidInput(message),
            Native.EcliptixErrorCode.ErrorInvalidState => EcliptixProtocolFailure.InvalidInput(message),
            Native.EcliptixErrorCode.ErrorPqMissing => EcliptixProtocolFailure.Decode(message),
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
