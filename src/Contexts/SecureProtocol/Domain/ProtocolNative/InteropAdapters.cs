using System;
using System.Runtime.InteropServices;
using System.Text;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.SharedKernel;

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
        NativeInterop.EppErrorCode result = NativeInterop.epp_identity_create(
            out IntPtr handle,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        if (handle == IntPtr.Zero)
        {
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(
                    "Identity keys creation returned null handle despite success status"));
        }

        return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Ok(new EcliptixIdentityKeys(handle));
    }

    public static Result<EcliptixIdentityKeys, EcliptixProtocolFailure> CreateFromSeed(byte[] seed,
        string? context = null)
    {
        if (seed == null)
        {
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Seed is null"));
        }

        if (context is null)
        {
            return CreateFromSeed(seed);
        }

        NativeInterop.EppErrorCode result = NativeInterop.epp_identity_create_with_context(
            seed,
            (nuint)seed.Length,
            context,
            (nuint)context.Length,
            out IntPtr handle,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        if (handle == IntPtr.Zero)
        {
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(
                    "Identity keys creation returned null handle despite success status"));
        }

        return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Ok(new EcliptixIdentityKeys(handle));
    }

    public static Result<EcliptixIdentityKeys, EcliptixProtocolFailure> CreateFromSeed(byte[] seed)
    {
        if (seed == null)
        {
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Seed is null"));
        }

        NativeInterop.EppErrorCode result = NativeInterop.epp_identity_create_from_seed(
            seed,
            (nuint)seed.Length,
            out IntPtr handle,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        if (handle == IntPtr.Zero)
        {
            return Result<EcliptixIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(
                    "Identity keys creation returned null handle despite success status"));
        }

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
        NativeInterop.EppErrorCode result = NativeInterop.epp_identity_get_x25519_public(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
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
        NativeInterop.EppErrorCode result = NativeInterop.epp_identity_get_ed25519_public(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicKyber()
    {
        ThrowIfDisposed();

        if (_handle == IntPtr.Zero)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration("Identity keys handle is zero (not disposed but invalid)"));
        }

        byte[] publicKey = new byte[1184];
        NativeInterop.EppErrorCode result = NativeInterop.epp_identity_get_kyber_public(
            _handle,
            publicKey,
            (nuint)publicKey.Length,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration(message));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(publicKey);
    }

    public Result<byte[], EcliptixProtocolFailure> CreatePreKeyBundle()
    {
        ThrowIfDisposed();

        NativeInterop.EppErrorCode result = NativeInterop.epp_prekey_bundle_create(
            _handle,
            out NativeInterop.EppBuffer buffer,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, message));
        }

        return InteropHelpers.CopyBuffer(ref buffer, "PreKey bundle");
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
            NativeInterop.epp_identity_destroy(_handle);
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

public sealed class HandshakeResponder : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    internal IntPtr Handle => _handle;

    public static Result<HandshakeResponderStart, EcliptixProtocolFailure> Start(
        EcliptixIdentityKeys identityKeys,
        byte[] localPreKeyBundle,
        byte[] handshakeInit,
        uint maxMessagesPerChain)
    {
        if (identityKeys == null || identityKeys.IsDisposed)
        {
            return Result<HandshakeResponderStart, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Identity keys are null or disposed"));
        }

        if (localPreKeyBundle == null)
        {
            return Result<HandshakeResponderStart, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Local prekey bundle is null"));
        }

        if (handshakeInit == null)
        {
            return Result<HandshakeResponderStart, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Handshake init is null"));
        }

        if (maxMessagesPerChain == 0)
        {
            return Result<HandshakeResponderStart, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Max messages per chain must be greater than zero"));
        }

        NativeInterop.EppSessionConfig config = new() { MaxMessagesPerChain = maxMessagesPerChain };

        NativeInterop.EppErrorCode result = NativeInterop.epp_handshake_responder_start(
            identityKeys.Handle,
            localPreKeyBundle,
            (nuint)localPreKeyBundle.Length,
            handshakeInit,
            (nuint)handshakeInit.Length,
            ref config,
            out IntPtr handle,
            out NativeInterop.EppBuffer buffer,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<HandshakeResponderStart, EcliptixProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, message));
        }

        Result<byte[], EcliptixProtocolFailure> messageResult = InteropHelpers.CopyBuffer(ref buffer, "Handshake ack");
        if (messageResult.IsErr)
        {
            NativeInterop.epp_handshake_responder_destroy(handle);
            return Result<HandshakeResponderStart, EcliptixProtocolFailure>.Err(messageResult.UnwrapErr());
        }

        HandshakeResponder responder = new HandshakeResponder(handle);
        return Result<HandshakeResponderStart, EcliptixProtocolFailure>.Ok(
            new HandshakeResponderStart(responder, messageResult.Unwrap()));
    }

    public Result<EcliptixSession, EcliptixProtocolFailure> Finish()
    {
        ThrowIfDisposed();

        NativeInterop.EppErrorCode result = NativeInterop.epp_handshake_responder_finish(
            _handle,
            out IntPtr sessionHandle,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<EcliptixSession, EcliptixProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, message));
        }

        Dispose();
        return Result<EcliptixSession, EcliptixProtocolFailure>.Ok(new EcliptixSession(sessionHandle));
    }

    private HandshakeResponder(IntPtr handle)
    {
        _handle = handle;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(HandshakeResponder));
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
            NativeInterop.epp_handshake_responder_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~HandshakeResponder()
    {
        Dispose();
    }
}

public sealed class HandshakeResponderStart
{
    public HandshakeResponder Responder { get; }
    public byte[] HandshakeAck { get; }

    internal HandshakeResponderStart(HandshakeResponder responder, byte[] handshakeAck)
    {
        Responder = responder;
        HandshakeAck = handshakeAck;
    }
}

public sealed class EcliptixSession : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    internal IntPtr Handle => _handle;

    public static Result<EcliptixSession, EcliptixProtocolFailure> Deserialize(byte[] state)
    {
        if (state == null)
        {
            return Result<EcliptixSession, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("State bytes are null"));
        }

        NativeInterop.EppErrorCode result = NativeInterop.epp_session_deserialize(
            state,
            (nuint)state.Length,
            out IntPtr handle,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<EcliptixSession, EcliptixProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, message));
        }

        return Result<EcliptixSession, EcliptixProtocolFailure>.Ok(new EcliptixSession(handle));
    }

    public Result<byte[], EcliptixProtocolFailure> Encrypt(
        byte[] plaintext,
        EnvelopeType envelopeType,
        uint envelopeId,
        string? correlationId = null)
    {
        ThrowIfDisposed();

        if (!TryMapEnvelopeType(envelopeType, out NativeInterop.EppEnvelopeType nativeEnvelopeType))
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput($"Unsupported envelope type: {envelopeType}"));
        }

        if (plaintext == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Plaintext is null"));
        }

        byte[]? correlationBytes = null;
        if (!string.IsNullOrEmpty(correlationId))
        {
            correlationBytes = Encoding.UTF8.GetBytes(correlationId);
        }

        NativeInterop.EppErrorCode result = NativeInterop.epp_session_encrypt(
            _handle,
            plaintext,
            (nuint)plaintext.Length,
            nativeEnvelopeType,
            envelopeId,
            correlationBytes,
            (nuint)(correlationBytes?.Length ?? 0),
            out NativeInterop.EppBuffer buffer,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, message));
        }

        return InteropHelpers.CopyBuffer(ref buffer, "Encrypted envelope");
    }

    private static bool TryMapEnvelopeType(
        EnvelopeType envelopeType,
        out NativeInterop.EppEnvelopeType nativeEnvelopeType)
    {
        switch (envelopeType)
        {
            case EnvelopeType.Request:
                nativeEnvelopeType = NativeInterop.EppEnvelopeType.Request;
                return true;
            case EnvelopeType.Response:
                nativeEnvelopeType = NativeInterop.EppEnvelopeType.Response;
                return true;
            case EnvelopeType.Notification:
                nativeEnvelopeType = NativeInterop.EppEnvelopeType.Notification;
                return true;
            case EnvelopeType.Heartbeat:
                nativeEnvelopeType = NativeInterop.EppEnvelopeType.Heartbeat;
                return true;
            case EnvelopeType.ErrorResponse:
                nativeEnvelopeType = NativeInterop.EppEnvelopeType.ErrorResponse;
                return true;
            default:
                nativeEnvelopeType = default;
                return false;
        }
    }

    public Result<SessionDecryptResult, EcliptixProtocolFailure> Decrypt(byte[] encryptedEnvelope)
    {
        ThrowIfDisposed();

        if (encryptedEnvelope == null)
        {
            return Result<SessionDecryptResult, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Encrypted envelope is null"));
        }

        NativeInterop.EppErrorCode result = NativeInterop.epp_session_decrypt(
            _handle,
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            out NativeInterop.EppBuffer plaintextBuffer,
            out NativeInterop.EppBuffer metadataBuffer,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<SessionDecryptResult, EcliptixProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, message));
        }

        var plaintextResult = InteropHelpers.CopyBuffer(ref plaintextBuffer, "Plaintext");
        if (plaintextResult.IsErr)
        {
            NativeInterop.epp_buffer_release(ref metadataBuffer);
            return Result<SessionDecryptResult, EcliptixProtocolFailure>.Err(plaintextResult.UnwrapErr());
        }

        var metadataResult = InteropHelpers.CopyBuffer(ref metadataBuffer, "Metadata");
        if (metadataResult.IsErr)
        {
            return Result<SessionDecryptResult, EcliptixProtocolFailure>.Err(metadataResult.UnwrapErr());
        }

        return Result<SessionDecryptResult, EcliptixProtocolFailure>.Ok(
            new SessionDecryptResult(plaintextResult.Unwrap(), metadataResult.Unwrap()));
    }

    public Result<byte[], EcliptixProtocolFailure> Serialize()
    {
        ThrowIfDisposed();

        NativeInterop.EppErrorCode result = NativeInterop.epp_session_serialize(
            _handle,
            out NativeInterop.EppBuffer buffer,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, message));
        }

        return InteropHelpers.CopyBuffer(ref buffer, "Session state");
    }

    internal EcliptixSession(IntPtr handle)
    {
        _handle = handle;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcliptixSession));
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
            NativeInterop.epp_session_destroy(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~EcliptixSession()
    {
        Dispose();
    }
}

public sealed class SessionDecryptResult
{
    public byte[] Plaintext { get; }
    public byte[] Metadata { get; }

    internal SessionDecryptResult(byte[] plaintext, byte[] metadata)
    {
        Plaintext = plaintext;
        Metadata = metadata;
    }
}

public static class ProtocolUtilities
{
    public static Result<Unit, EcliptixProtocolFailure> ValidateEnvelope(byte[] encryptedEnvelope)
    {
        if (encryptedEnvelope == null)
        {
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Encrypted envelope is null"));
        }

        NativeInterop.EppErrorCode result = NativeInterop.epp_envelope_validate(
            encryptedEnvelope,
            (nuint)encryptedEnvelope.Length,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<Unit, EcliptixProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, message));
        }

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    public static Result<byte[], EcliptixProtocolFailure> DeriveRootKey(
        byte[] opaqueSessionKey,
        byte[] userContext)
    {
        if (opaqueSessionKey == null || opaqueSessionKey.Length == 0)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Opaque session key is null or empty"));
        }

        if (userContext == null || userContext.Length == 0)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("User context is null or empty"));
        }

        byte[] rootKey = new byte[32];
        NativeInterop.EppErrorCode result = NativeInterop.epp_derive_root_key(
            opaqueSessionKey,
            (nuint)opaqueSessionKey.Length,
            userContext,
            (nuint)userContext.Length,
            rootKey,
            (nuint)rootKey.Length,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, message));
        }

        return Result<byte[], EcliptixProtocolFailure>.Ok(rootKey);
    }

    public static Result<ShamirSplitResult, EcliptixProtocolFailure> ShamirSplit(
        byte[] secret,
        byte threshold,
        byte shareCount,
        byte[] authKey)
    {
        if (secret == null || secret.Length == 0)
        {
            return Result<ShamirSplitResult, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Secret is null or empty"));
        }

        if (authKey == null)
        {
            return Result<ShamirSplitResult, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Auth key is null"));
        }

        NativeInterop.EppErrorCode result = NativeInterop.epp_shamir_split(
            secret,
            (nuint)secret.Length,
            threshold,
            shareCount,
            authKey,
            (nuint)authKey.Length,
            out NativeInterop.EppBuffer sharesBuffer,
            out nuint shareLength,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<ShamirSplitResult, EcliptixProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, message));
        }

        var sharesResult = InteropHelpers.CopyBuffer(ref sharesBuffer, "Shares");
        if (sharesResult.IsErr)
        {
            return Result<ShamirSplitResult, EcliptixProtocolFailure>.Err(sharesResult.UnwrapErr());
        }

        if (shareLength > int.MaxValue)
        {
            return Result<ShamirSplitResult, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.DataTooLarge("Share length exceeds maximum array size"));
        }

        return Result<ShamirSplitResult, EcliptixProtocolFailure>.Ok(
            new ShamirSplitResult(sharesResult.Unwrap(), (int)shareLength));
    }

    public static Result<byte[], EcliptixProtocolFailure> ShamirReconstruct(
        byte[] shares,
        int shareLength,
        int shareCount,
        byte[] authKey)
    {
        if (shares == null || shares.Length == 0)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Shares are null or empty"));
        }

        if (shareLength <= 0 || shareCount <= 0)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Share length or count is invalid"));
        }

        if (authKey == null)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Auth key is null"));
        }

        NativeInterop.EppErrorCode result = NativeInterop.epp_shamir_reconstruct(
            shares,
            (nuint)shares.Length,
            (nuint)shareLength,
            (nuint)shareCount,
            authKey,
            (nuint)authKey.Length,
            out NativeInterop.EppBuffer secretBuffer,
            out NativeInterop.EppError error);

        if (result != NativeInterop.EppErrorCode.Success)
        {
            string message = error.GetMessage();
            NativeInterop.epp_error_free(ref error);
            return Result<byte[], EcliptixProtocolFailure>.Err(
                InteropHelpers.ConvertError(result, message));
        }

        return InteropHelpers.CopyBuffer(ref secretBuffer, "Secret");
    }
}

public sealed class ShamirSplitResult
{
    public byte[] Shares { get; }
    public int ShareLength { get; }

    internal ShamirSplitResult(byte[] shares, int shareLength)
    {
        Shares = shares;
        ShareLength = shareLength;
    }
}

internal static class InteropHelpers
{
    public static Result<byte[], EcliptixProtocolFailure> CopyBuffer(ref NativeInterop.EppBuffer buffer, string label)
    {
        try
        {
            if (buffer.Length == 0)
            {
                return Result<byte[], EcliptixProtocolFailure>.Ok(Array.Empty<byte>());
            }

            if (buffer.Data == IntPtr.Zero)
            {
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput($"{label} buffer is null"));
            }

            if (buffer.Length > int.MaxValue)
            {
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.DataTooLarge($"{label} length exceeds maximum array size"));
            }

            byte[] data = new byte[(int)buffer.Length];
            Marshal.Copy(buffer.Data, data, 0, data.Length);
            return Result<byte[], EcliptixProtocolFailure>.Ok(data);
        }
        finally
        {
            NativeInterop.epp_buffer_release(ref buffer);
        }
    }

    public static EcliptixProtocolFailure ConvertError(NativeInterop.EppErrorCode code, string message) =>
        code switch
        {
            NativeInterop.EppErrorCode.ErrorInvalidInput => EcliptixProtocolFailure.InvalidInput(message),
            NativeInterop.EppErrorCode.ErrorKeyGeneration => EcliptixProtocolFailure.KeyGeneration(message),
            NativeInterop.EppErrorCode.ErrorDeriveKey => EcliptixProtocolFailure.DeriveKey(message),
            NativeInterop.EppErrorCode.ErrorHandshake => EcliptixProtocolFailure.Handshake(message),
            NativeInterop.EppErrorCode.ErrorEncryption => EcliptixProtocolFailure.SessionAuthFailed(message),
            NativeInterop.EppErrorCode.ErrorDecryption => EcliptixProtocolFailure.SessionAuthFailed(message),
            NativeInterop.EppErrorCode.ErrorDecode => EcliptixProtocolFailure.Decode(message),
            NativeInterop.EppErrorCode.ErrorEncode => EcliptixProtocolFailure.Decode(message),
            NativeInterop.EppErrorCode.ErrorBufferTooSmall => EcliptixProtocolFailure.BufferTooSmall(message),
            NativeInterop.EppErrorCode.ErrorObjectDisposed => EcliptixProtocolFailure.ObjectDisposed(message),
            NativeInterop.EppErrorCode.ErrorPrepareLocal => EcliptixProtocolFailure.PrepareLocal(message),
            NativeInterop.EppErrorCode.ErrorReplayAttack => EcliptixProtocolFailure.ReplayAttempt(message),
            NativeInterop.EppErrorCode.ErrorSessionExpired => EcliptixProtocolFailure.SessionAuthFailed(message),
            NativeInterop.EppErrorCode.ErrorOutOfMemory => EcliptixProtocolFailure.AllocationFailed(message),
            NativeInterop.EppErrorCode.ErrorSodiumFailure => EcliptixProtocolFailure.MemoryBufferError(message),
            NativeInterop.EppErrorCode.ErrorNullPointer => EcliptixProtocolFailure.InvalidInput(message),
            NativeInterop.EppErrorCode.ErrorInvalidState => EcliptixProtocolFailure.StateMismatch(message),
            NativeInterop.EppErrorCode.ErrorPqMissing => EcliptixProtocolFailure.Handshake(message),
            _ => EcliptixProtocolFailure.Generic(message)
        };
}
