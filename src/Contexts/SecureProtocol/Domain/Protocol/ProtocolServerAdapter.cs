using Ecliptix.Protobuf.Protocol;
using Ecliptix.SecureProtocol.Domain.ProtocolNative;
using Ecliptix.SharedKernel;
using Native = Ecliptix.SecureProtocol.Domain.ProtocolNative.NativeInterop;

namespace Ecliptix.SecureProtocol.Domain.Protocol;

public sealed class ProtocolServerAdapter : IProtocolServer
{
    private static readonly object InitLock = new();
    private static int _nativeInitRefCount;
    private static bool _nativeInitialized;
    private bool _initialized;

    public Result<Unit, EcliptixProtocolFailure> Initialize()
    {
        lock (InitLock)
        {
            if (_initialized)
            {
                return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
            }

            if (!_nativeInitialized)
            {
                Native.EppErrorCode result = Native.epp_init();
                if (result != Native.EppErrorCode.Success)
                {
                    return Result<Unit, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"Failed to initialize native protocol: {Native.ErrorCodeToString(result)}"));
                }

                _nativeInitialized = true;
            }

            _nativeInitRefCount++;
            _initialized = true;
            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }
    }

    public Result<Unit, EcliptixProtocolFailure> Shutdown()
    {
        lock (InitLock)
        {
            if (!_initialized)
            {
                return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
            }

            _initialized = false;

            if (_nativeInitialized && _nativeInitRefCount > 0)
            {
                _nativeInitRefCount--;
                if (_nativeInitRefCount == 0)
                {
                    Native.epp_shutdown();
                    _nativeInitialized = false;
                }
            }

            return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
        }
    }

    public Result<ProtocolIdentity, EcliptixProtocolFailure> CreateIdentity(byte[]? seed = null, Guid? accountId = null)
    {
        Result<EcliptixIdentityKeys, EcliptixProtocolFailure> createResult = seed switch
        {
            null => EcliptixIdentityKeys.Create(),
            _ when accountId.HasValue => EcliptixIdentityKeys.CreateFromSeed(seed, accountId.Value.ToString()),
            _ => EcliptixIdentityKeys.CreateFromSeed(seed)
        };

        if (createResult.IsErr)
        {
            return Result<ProtocolIdentity, EcliptixProtocolFailure>.Err(createResult.UnwrapErr());
        }

        return Result<ProtocolIdentity, EcliptixProtocolFailure>.Ok(new ProtocolIdentity(createResult.Unwrap()));
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicEd25519(ProtocolIdentity identity)
    {
        if (identity.IsDisposed)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolIdentity)));
        }

        return identity.Handle.GetPublicEd25519();
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicX25519(ProtocolIdentity identity)
    {
        if (identity.IsDisposed)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolIdentity)));
        }

        return identity.Handle.GetPublicX25519();
    }

    public Result<byte[], EcliptixProtocolFailure> GetPublicKyber(ProtocolIdentity identity)
    {
        if (identity.IsDisposed)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolIdentity)));
        }

        return identity.Handle.GetPublicKyber();
    }

    public Result<byte[], EcliptixProtocolFailure> CreatePreKeyBundle(ProtocolIdentity identity)
    {
        if (identity.IsDisposed)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolIdentity)));
        }

        return identity.Handle.CreatePreKeyBundle();
    }

    public Result<ProtocolHandshakeResponderStart, EcliptixProtocolFailure> StartHandshakeResponder(
        ProtocolIdentity identity,
        byte[] localPreKeyBundle,
        byte[] handshakeInit,
        uint maxMessagesPerChain)
    {
        if (identity.IsDisposed)
        {
            return Result<ProtocolHandshakeResponderStart, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolIdentity)));
        }

        Result<HandshakeResponderStart, EcliptixProtocolFailure> startResult =
            HandshakeResponder.Start(identity.Handle, localPreKeyBundle, handshakeInit, maxMessagesPerChain);

        if (startResult.IsErr)
        {
            return Result<ProtocolHandshakeResponderStart, EcliptixProtocolFailure>.Err(startResult.UnwrapErr());
        }

        HandshakeResponderStart start = startResult.Unwrap();
        return Result<ProtocolHandshakeResponderStart, EcliptixProtocolFailure>.Ok(
            new ProtocolHandshakeResponderStart(
                new ProtocolHandshakeResponder(start.Responder),
                start.HandshakeAck));
    }

    public Result<ProtocolSession, EcliptixProtocolFailure> FinishHandshakeResponder(
        ProtocolHandshakeResponder responder)
    {
        if (responder.IsDisposed)
        {
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolHandshakeResponder)));
        }

        Result<EcliptixSession, EcliptixProtocolFailure> finishResult = responder.Handle.Finish();
        if (finishResult.IsErr)
        {
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(finishResult.UnwrapErr());
        }

        return Result<ProtocolSession, EcliptixProtocolFailure>.Ok(new ProtocolSession(finishResult.Unwrap()));
    }

    public Result<byte[], EcliptixProtocolFailure> Encrypt(
        ProtocolSession session,
        byte[] plaintext,
        EnvelopeType envelopeType,
        uint envelopeId,
        string? correlationId = null)
    {
        return EnsureSessionActive(
            session,
            () => session.Handle.Encrypt(plaintext, envelopeType, envelopeId, correlationId));
    }

    public Result<ProtocolDecryptResult, EcliptixProtocolFailure> Decrypt(
        ProtocolSession session,
        byte[] encryptedEnvelope)
    {
        Result<SessionDecryptResult, EcliptixProtocolFailure> decryptResult =
            EnsureSessionActive(session, () => session.Handle.Decrypt(encryptedEnvelope));

        if (decryptResult.IsErr)
        {
            return Result<ProtocolDecryptResult, EcliptixProtocolFailure>.Err(decryptResult.UnwrapErr());
        }

        SessionDecryptResult decrypted = decryptResult.Unwrap();
        return Result<ProtocolDecryptResult, EcliptixProtocolFailure>.Ok(
            new ProtocolDecryptResult(decrypted.Plaintext, decrypted.Metadata));
    }

    public Result<byte[], EcliptixProtocolFailure> ExportState(ProtocolSession session)
    {
        return EnsureSessionActive(session, () => session.Handle.Serialize());
    }

    public Result<ProtocolSession, EcliptixProtocolFailure> ImportState(byte[] stateBytes)
    {
        Result<EcliptixSession, EcliptixProtocolFailure> importResult = EcliptixSession.Deserialize(stateBytes);
        if (importResult.IsErr)
        {
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(importResult.UnwrapErr());
        }

        return Result<ProtocolSession, EcliptixProtocolFailure>.Ok(new ProtocolSession(importResult.Unwrap()));
    }

    public Result<Unit, EcliptixProtocolFailure> ValidateEnvelope(byte[] encryptedEnvelope)
    {
        return ProtocolUtilities.ValidateEnvelope(encryptedEnvelope);
    }

    public void Dispose()
    {
        Shutdown();
    }

    private static Result<T, EcliptixProtocolFailure> EnsureSessionActive<T>(
        ProtocolSession session,
        Func<Result<T, EcliptixProtocolFailure>> action)
    {
        if (session.IsDisposed)
        {
            return Result<T, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolSession)));
        }

        return action();
    }
}
