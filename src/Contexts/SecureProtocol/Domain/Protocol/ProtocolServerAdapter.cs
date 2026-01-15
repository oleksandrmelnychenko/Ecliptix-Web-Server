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

    public Result<ProtocolSession, EcliptixProtocolFailure> CreateSession(
        ProtocolIdentity identity,
        Action<uint>? onStateChanged = null)
    {
        if (identity.IsDisposed)
        {
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolIdentity)));
        }

        Result<EcliptixProtocolSystem, EcliptixProtocolFailure> createResult =
            EcliptixProtocolSystem.Create(identity.Handle);

        if (createResult.IsErr)
        {
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(createResult.UnwrapErr());
        }

        EcliptixProtocolSystem wrapper = createResult.Unwrap();
        Result<Unit, EcliptixProtocolFailure> callbackResult = wrapper.SetEventHandler(onStateChanged);
        if (callbackResult.IsErr)
        {
            wrapper.Dispose();
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(callbackResult.UnwrapErr());
        }

        return Result<ProtocolSession, EcliptixProtocolFailure>.Ok(new ProtocolSession(wrapper));
    }

    public Result<ProtocolSession, EcliptixProtocolFailure> CreateSessionFromRoot(
        ProtocolIdentity identity,
        byte[] rootKey,
        byte[] peerBundle,
        bool isInitiator,
        Action<uint>? onStateChanged = null)
    {
        if (identity.IsDisposed)
        {
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolIdentity)));
        }

        Result<EcliptixProtocolSystem, EcliptixProtocolFailure> createResult =
            EcliptixProtocolSystem.CreateFromRoot(identity.Handle, rootKey, peerBundle, isInitiator);

        if (createResult.IsErr)
        {
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(createResult.UnwrapErr());
        }

        EcliptixProtocolSystem wrapper = createResult.Unwrap();
        Result<Unit, EcliptixProtocolFailure> callbackResult = wrapper.SetEventHandler(onStateChanged);
        if (callbackResult.IsErr)
        {
            wrapper.Dispose();
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(callbackResult.UnwrapErr());
        }

        return Result<ProtocolSession, EcliptixProtocolFailure>.Ok(new ProtocolSession(wrapper));
    }

    public Result<ProtocolSession, EcliptixProtocolFailure> ImportState(
        ProtocolIdentity identity,
        byte[] stateBytes,
        Action<uint>? onStateChanged = null)
    {
        if (identity.IsDisposed)
        {
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(ProtocolIdentity)));
        }

        Result<EcliptixProtocolSystem, EcliptixProtocolFailure> importResult =
            EcliptixProtocolSystem.ImportState(identity.Handle, stateBytes);

        if (importResult.IsErr)
        {
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(importResult.UnwrapErr());
        }

        EcliptixProtocolSystem wrapper = importResult.Unwrap();
        Result<Unit, EcliptixProtocolFailure> callbackResult = wrapper.SetEventHandler(onStateChanged);
        if (callbackResult.IsErr)
        {
            wrapper.Dispose();
            return Result<ProtocolSession, EcliptixProtocolFailure>.Err(callbackResult.UnwrapErr());
        }

        return Result<ProtocolSession, EcliptixProtocolFailure>.Ok(new ProtocolSession(wrapper));
    }

    public Result<byte[], EcliptixProtocolFailure> BeginHandshake(
        ProtocolSession session,
        uint connectionId,
        PubKeyExchangeType exchangeType,
        byte[] peerKyberPublicKey)
    {
        return EnsureSessionActive(
            session,
            () => session.Handle.BeginHandshake(connectionId, exchangeType, peerKyberPublicKey));
    }

    public Result<Unit, EcliptixProtocolFailure> CompleteHandshake(
        ProtocolSession session,
        byte[] peerHandshakeMessage,
        byte[] rootKey)
    {
        return EnsureSessionActive(session, () => session.Handle.CompleteHandshake(peerHandshakeMessage, rootKey));
    }

    public Result<Unit, EcliptixProtocolFailure> CompleteHandshakeAuto(
        ProtocolSession session,
        byte[] peerHandshakeMessage)
    {
        return EnsureSessionActive(session, () => session.Handle.CompleteHandshakeAuto(peerHandshakeMessage));
    }

    public Result<byte[], EcliptixProtocolFailure> SendMessage(ProtocolSession session, byte[] plaintext)
    {
        return EnsureSessionActive(session, () => session.Handle.SendMessage(plaintext));
    }

    public Result<byte[], EcliptixProtocolFailure> ReceiveMessage(ProtocolSession session, byte[] encryptedEnvelope)
    {
        return EnsureSessionActive(session, () => session.Handle.ReceiveMessage(encryptedEnvelope));
    }

    public Result<bool, EcliptixProtocolFailure> HasConnection(ProtocolSession session)
    {
        return EnsureSessionActive(session, () => session.Handle.HasConnection());
    }

    public Result<uint, EcliptixProtocolFailure> GetConnectionId(ProtocolSession session)
    {
        return EnsureSessionActive(session, () => session.Handle.GetConnectionId());
    }

    public Result<uint?, EcliptixProtocolFailure> GetSelectedOpkId(ProtocolSession session)
    {
        return EnsureSessionActive(session, () => session.Handle.GetSelectedOpkId());
    }

    public Result<byte[], EcliptixProtocolFailure> ExportState(ProtocolSession session)
    {
        return EnsureSessionActive(session, () => session.Handle.ExportState());
    }

    public Result<Unit, EcliptixProtocolFailure> ValidateEnvelopeHybridRequirements(byte[] encryptedEnvelope)
    {
        return EcliptixProtocolSystem.ValidateEnvelopeHybridRequirements(encryptedEnvelope);
    }

    public Result<byte[], EcliptixProtocolFailure> DeriveRootFromOpaqueSessionKey(
        byte[] opaqueSessionKey,
        byte[] userContext)
    {
        return EcliptixProtocolSystem.DeriveRootFromOpaqueSessionKey(opaqueSessionKey, userContext);
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
