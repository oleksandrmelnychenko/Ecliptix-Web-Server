using System;
using System.Runtime.InteropServices;
using Ecliptix.SharedKernel;

namespace Ecliptix.Core.Domain.ProtocolNative;

public sealed class EcliptixProtocolSystemWrapper : IDisposable
{
    private IntPtr _handle;
    private readonly EcliptixIdentityKeysWrapper _identityKeys;
    private bool _disposed;
    private GCHandle _callbackHandle;
    private EcliptixCallbacks _callbacks;
    private static bool _chainIndicesSupported = true;

    private EcliptixProtocolSystemWrapper(IntPtr handle, EcliptixIdentityKeysWrapper identityKeys)
    {
        _handle = handle;
        _identityKeys = identityKeys;
        _disposed = false;
    }

    public static Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure> Create(
        EcliptixIdentityKeysWrapper identityKeys)
    {
        if (identityKeys == null || identityKeys.IsDisposed)
        {
            return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Identity keys are null or disposed"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_create(
            identityKeys.Handle,
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Err(
                ConvertError(result, errorMessage));
        }

        return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Ok(
            new EcliptixProtocolSystemWrapper(handle, identityKeys));
    }

    public static Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure> CreateFromRoot(
        EcliptixIdentityKeysWrapper identityKeys,
        byte[] rootKey,
        byte[] peerBundle,
        bool isInitiator)
    {
        if (identityKeys == null || identityKeys.IsDisposed)
        {
            return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Identity keys are null or disposed"));
        }
        if (rootKey == null || rootKey.Length != 32)
        {
            return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Root key must be 32 bytes"));
        }
        if (peerBundle == null || peerBundle.Length == 0)
        {
            return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Peer bundle is missing"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_create_from_root(
            identityKeys.Handle,
            rootKey,
            (nuint)rootKey.Length,
            peerBundle,
            (nuint)peerBundle.Length,
            isInitiator,
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Err(
                ConvertError(result, errorMessage));
        }

        return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Ok(
            new EcliptixProtocolSystemWrapper(handle, identityKeys));
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
            EcliptixProtocolEventCallback callback = (connectionId, _) => { onProtocolStateChanged(connectionId); };
            _callbackHandle = GCHandle.Alloc(callback);

            _callbacks = new EcliptixCallbacks
            {
                OnProtocolStateChanged = callback,
                UserData = IntPtr.Zero
            };

            EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_set_callbacks(
                _handle,
                in _callbacks,
                out EcliptixError error);

            if (result != EcliptixErrorCode.Success)
            {
                string errorMessage = error.GetMessage();
                EcliptixNativeInterop.ecliptix_error_free(ref error);
                _callbackHandle.Free();
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Failed to set callbacks: {errorMessage}"));
            }
        }
        else
        {
            _callbacks = new EcliptixCallbacks
            {
                OnProtocolStateChanged = null,
                UserData = IntPtr.Zero
            };

            EcliptixNativeInterop.ecliptix_protocol_system_set_callbacks(
                _handle,
                in _callbacks,
                out _);
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public Result<byte[], EcliptixProtocolFailure> SendMessage(byte[] plaintext)
    {
        ThrowIfDisposed();
        if (plaintext == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Plaintext is null"));
        }

        IntPtr bufferPtr = EcliptixNativeInterop.ecliptix_buffer_allocate(0);
        if (bufferPtr == IntPtr.Zero)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to allocate native buffer"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_send_message(
            _handle,
            plaintext,
            (nuint)plaintext.Length,
            bufferPtr,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            EcliptixNativeInterop.ecliptix_buffer_free(bufferPtr);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, errorMessage));
        }

        try
        {
            EcliptixBuffer buffer = Marshal.PtrToStructure<EcliptixBuffer>(bufferPtr);
            byte[] encrypted = new byte[buffer.Length];
            Marshal.Copy(buffer.Data, encrypted, 0, (int)buffer.Length);
            return Result<byte[], EcliptixProtocolFailure>.Ok(encrypted);
        }
        finally
        {
            EcliptixNativeInterop.ecliptix_buffer_free(bufferPtr);
        }
    }

    public Result<byte[], EcliptixProtocolFailure> ReceiveMessage(byte[] encryptedEnvelope)
    {
        ThrowIfDisposed();
        if (encryptedEnvelope == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Encrypted envelope is null"));
        }

        IntPtr bufferPtr = EcliptixNativeInterop.ecliptix_buffer_allocate(0);
        if (bufferPtr == IntPtr.Zero)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to allocate native buffer"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_receive_message(
            _handle,
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            bufferPtr,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            EcliptixNativeInterop.ecliptix_buffer_free(bufferPtr);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, errorMessage));
        }

        try
        {
            EcliptixBuffer buffer = Marshal.PtrToStructure<EcliptixBuffer>(bufferPtr);
            byte[] plaintext = new byte[buffer.Length];
            Marshal.Copy(buffer.Data, plaintext, 0, (int)buffer.Length);
            return Result<byte[], EcliptixProtocolFailure>.Ok(plaintext);
        }
        finally
        {
            EcliptixNativeInterop.ecliptix_buffer_free(bufferPtr);
        }
    }

    public Result<byte[], EcliptixProtocolFailure> BeginHandshake(uint connectionId, byte exchangeType)
    {
        ThrowIfDisposed();

        IntPtr bufferPtr = EcliptixNativeInterop.ecliptix_buffer_allocate(0);
        if (bufferPtr == IntPtr.Zero)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to allocate native buffer"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_begin_handshake(
            _handle,
            connectionId,
            exchangeType,
            bufferPtr,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            EcliptixNativeInterop.ecliptix_buffer_free(bufferPtr);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, errorMessage));
        }

        try
        {
            EcliptixBuffer buffer = Marshal.PtrToStructure<EcliptixBuffer>(bufferPtr);
            byte[] handshake = new byte[buffer.Length];
            Marshal.Copy(buffer.Data, handshake, 0, (int)buffer.Length);
            return Result<byte[], EcliptixProtocolFailure>.Ok(handshake);
        }
        finally
        {
            EcliptixNativeInterop.ecliptix_buffer_free(bufferPtr);
        }
    }

    public Result<byte[], EcliptixProtocolFailure> BeginHandshakeWithPeerKyber(
        uint connectionId,
        byte exchangeType,
        byte[] peerKyberPublicKey)
    {
        ThrowIfDisposed();

        if (peerKyberPublicKey == null || peerKyberPublicKey.Length != 1184)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Peer Kyber public key must be 1184 bytes"));
        }

        IntPtr bufferPtr = EcliptixNativeInterop.ecliptix_buffer_allocate(0);
        if (bufferPtr == IntPtr.Zero)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to allocate native buffer"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_begin_handshake_with_peer_kyber(
            _handle,
            connectionId,
            exchangeType,
            peerKyberPublicKey,
            (nuint)peerKyberPublicKey.Length,
            bufferPtr,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            EcliptixNativeInterop.ecliptix_buffer_free(bufferPtr);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, errorMessage));
        }

        try
        {
            EcliptixBuffer buffer = Marshal.PtrToStructure<EcliptixBuffer>(bufferPtr);
            byte[] handshake = new byte[buffer.Length];
            Marshal.Copy(buffer.Data, handshake, 0, (int)buffer.Length);
            return Result<byte[], EcliptixProtocolFailure>.Ok(handshake);
        }
        finally
        {
            EcliptixNativeInterop.ecliptix_buffer_free(bufferPtr);
        }
    }

    public Result<Unit, EcliptixProtocolFailure> CompleteHandshake(byte[] peerHandshakeMessage, byte[] rootKey)
    {
        ThrowIfDisposed();

        if (peerHandshakeMessage == null || rootKey == null)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Handshake or root key is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_complete_handshake(
            _handle,
            peerHandshakeMessage,
            (nuint)peerHandshakeMessage.Length,
            rootKey,
            (nuint)rootKey.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(ConvertError(result, errorMessage));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public Result<Unit, EcliptixProtocolFailure> CompleteHandshakeAuto(byte[] peerHandshakeMessage)
    {
        ThrowIfDisposed();

        if (peerHandshakeMessage == null)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Handshake is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_complete_handshake_auto(
            _handle,
            peerHandshakeMessage,
            (nuint)peerHandshakeMessage.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(ConvertError(result, errorMessage));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public Result<bool, EcliptixProtocolFailure> HasConnection()
    {
        ThrowIfDisposed();
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_has_connection(
            _handle,
            out bool hasConn,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<bool, EcliptixProtocolFailure>.Err(ConvertError(result, errorMessage));
        }

        return Result<bool, EcliptixProtocolFailure>.Ok(hasConn);
    }

    public EcliptixIdentityKeysWrapper GetIdentityKeys() => _identityKeys;

    public Result<uint, EcliptixProtocolFailure> GetConnectionId()
    {
        ThrowIfDisposed();
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_get_connection_id(
            _handle,
            out uint id,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<uint, EcliptixProtocolFailure>.Err(ConvertError(result, errorMessage));
        }

        return Result<uint, EcliptixProtocolFailure>.Ok(id);
    }

    public Result<(uint SendingIndex, uint ReceivingIndex), EcliptixProtocolFailure> GetChainIndices()
    {
        ThrowIfDisposed();

        if (!_chainIndicesSupported)
        {
            return Result<(uint, uint), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Native protocol does not expose chain indices"));
        }

        try
        {
            EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_get_chain_indices(
                _handle,
                out uint sendingIndex,
                out uint receivingIndex,
                out EcliptixError error);

            if (result != EcliptixErrorCode.Success)
            {
                string errorMessage = error.GetMessage();
                EcliptixNativeInterop.ecliptix_error_free(ref error);
                return Result<(uint, uint), EcliptixProtocolFailure>.Err(ConvertError(result, errorMessage));
            }

            return Result<(uint, uint), EcliptixProtocolFailure>.Ok((sendingIndex, receivingIndex));
        }
        catch (EntryPointNotFoundException)
        {
            _chainIndicesSupported = false;
            return Result<(uint, uint), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Native protocol missing chain index entry point"));
        }
    }

    public Result<byte[], EcliptixProtocolFailure> ExportState()
    {
        ThrowIfDisposed();
        IntPtr bufferPtr = EcliptixNativeInterop.ecliptix_buffer_allocate(0);
        if (bufferPtr == IntPtr.Zero)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to allocate native buffer"));
        }
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_export_state(
            _handle,
            bufferPtr,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            EcliptixNativeInterop.ecliptix_buffer_free(bufferPtr);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, errorMessage));
        }

        try
        {
            EcliptixBuffer buffer = Marshal.PtrToStructure<EcliptixBuffer>(bufferPtr);
            byte[] state = new byte[buffer.Length];
            Marshal.Copy(buffer.Data, state, 0, (int)buffer.Length);
            return Result<byte[], EcliptixProtocolFailure>.Ok(state);
        }
        finally
        {
            EcliptixNativeInterop.ecliptix_buffer_free(bufferPtr);
        }
    }

    public static Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure> ImportState(
        EcliptixIdentityKeysWrapper identityKeys,
        byte[] stateBytes)
    {
        if (identityKeys == null || identityKeys.IsDisposed)
        {
            return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Identity keys are null or disposed"));
        }
        if (stateBytes == null || stateBytes.Length == 0)
        {
            return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("State bytes are missing"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_protocol_system_import_state(
            identityKeys.Handle,
            stateBytes,
            (nuint)stateBytes.Length,
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Err(
                ConvertError(result, errorMessage));
        }

        return Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure>.Ok(
            new EcliptixProtocolSystemWrapper(handle, identityKeys));
    }

    public static Result<Unit, EcliptixProtocolFailure> ValidateEnvelopeHybridRequirements(byte[] encryptedEnvelope)
    {
        if (encryptedEnvelope == null)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Encrypted envelope is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_envelope_validate_hybrid_requirements(
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(
                ConvertError(result, errorMessage));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public static Result<byte[], EcliptixProtocolFailure> DeriveRootFromOpaqueSessionKey(
        byte[] opaqueSessionKey,
        byte[] userContext)
    {
        if (opaqueSessionKey == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("OPAQUE session key is null"));
        }
        if (userContext == null || userContext.Length == 0)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("OPAQUE user context is missing"));
        }

        byte[] rootKey = new byte[32];
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_derive_root_from_opaque_session_key(
            opaqueSessionKey,
            (nuint)opaqueSessionKey.Length,
            userContext,
            (nuint)userContext.Length,
            rootKey,
            (nuint)rootKey.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(ConvertError(result, errorMessage));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(rootKey);
    }

    private static EcliptixProtocolFailure ConvertError(EcliptixErrorCode code, string message)
    {
        return code switch
        {
            EcliptixErrorCode.ErrorInvalidInput => EcliptixProtocolFailure.InvalidInput(message),
            EcliptixErrorCode.ErrorKeyGeneration => EcliptixProtocolFailure.KeyGeneration(message),
            EcliptixErrorCode.ErrorDeriveKey => EcliptixProtocolFailure.DeriveKey(message),
            EcliptixErrorCode.ErrorHandshake => EcliptixProtocolFailure.Handshake(message),
            EcliptixErrorCode.ErrorEncryption => EcliptixProtocolFailure.Generic(message),
            EcliptixErrorCode.ErrorDecryption => EcliptixProtocolFailure.Generic(message),
            EcliptixErrorCode.ErrorDecode => EcliptixProtocolFailure.Decode(message),
            EcliptixErrorCode.ErrorPqMissing => EcliptixProtocolFailure.Decode(message),
            EcliptixErrorCode.ErrorBufferTooSmall => EcliptixProtocolFailure.BufferTooSmall(message),
            EcliptixErrorCode.ErrorObjectDisposed => EcliptixProtocolFailure.ObjectDisposed("Native protocol"),
            EcliptixErrorCode.ErrorPrepareLocal => EcliptixProtocolFailure.PrepareLocal(message),
            _ => EcliptixProtocolFailure.Generic(message)
        };
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcliptixProtocolSystemWrapper));
        }
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
            EcliptixNativeInterop.ecliptix_protocol_system_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~EcliptixProtocolSystemWrapper()
    {
        Dispose();
    }
}

public sealed class EcliptixIdentityKeysWrapper : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    public IntPtr Handle => _handle;
    public bool IsDisposed => _disposed;

    private EcliptixIdentityKeysWrapper(IntPtr handle)
    {
        _handle = handle;
        _disposed = false;
    }

    public static Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> Create()
    {
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_identity_keys_create(
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(errorMessage));
        }

        return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Ok(
            new EcliptixIdentityKeysWrapper(handle));
    }

    public static Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> CreateFromSeed(byte[] seed)
    {
        if (seed == null)
        {
            return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Seed is null"));
        }

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_identity_keys_create_from_seed(
            seed,
            (nuint)seed.Length,
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(errorMessage));
        }

        return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Ok(
            new EcliptixIdentityKeysWrapper(handle));
    }

    public static Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure> CreateFromSeed(
        byte[] seed,
        string accountId)
    {
        if (seed == null)
        {
            return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Seed is null"));
        }
        if (string.IsNullOrWhiteSpace(accountId))
        {
            return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Account id is missing"));
        }

        byte[] accountBytes = System.Text.Encoding.UTF8.GetBytes(accountId);

        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_identity_keys_create_from_seed_with_context(
            seed,
            (nuint)seed.Length,
            accountId,
            (nuint)accountBytes.Length,
            out IntPtr handle,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(errorMessage));
        }

        return Result<EcliptixIdentityKeysWrapper, EcliptixProtocolFailure>.Ok(
            new EcliptixIdentityKeysWrapper(handle));
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicX25519()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[32];
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_identity_keys_get_public_x25519(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(errorMessage));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicEd25519()
    {
        ThrowIfDisposed();

        byte[] publicKey = new byte[32];
        EcliptixErrorCode result = EcliptixNativeInterop.ecliptix_identity_keys_get_public_ed25519(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out EcliptixError error);

        if (result != EcliptixErrorCode.Success)
        {
            string errorMessage = error.GetMessage();
            EcliptixNativeInterop.ecliptix_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(errorMessage));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcliptixIdentityKeysWrapper));
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_handle != IntPtr.Zero)
        {
            EcliptixNativeInterop.ecliptix_identity_keys_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~EcliptixIdentityKeysWrapper()
    {
        Dispose();
    }
}
