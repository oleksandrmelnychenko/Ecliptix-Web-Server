using System;
using Ecliptix.SharedKernel;

namespace Ecliptix.Core.Domain.ProtocolNative;

public sealed class NativeProtocolSession : IDisposable
{
    private readonly EcliptixProtocolSystemWrapper _wrapper;
    private bool _disposed;

    private NativeProtocolSession(EcliptixProtocolSystemWrapper wrapper)
    {
        _wrapper = wrapper;
    }

    public static Result<NativeProtocolSession, EcliptixProtocolFailure> Create(EcliptixIdentityKeysWrapper identityKeys)
    {
        Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure> result =
            EcliptixProtocolSystemWrapper.Create(identityKeys);
        if (result.IsErr)
        {
            return Result<NativeProtocolSession, EcliptixProtocolFailure>.Err(result.UnwrapErr());
        }
        return Result<NativeProtocolSession, EcliptixProtocolFailure>.Ok(new NativeProtocolSession(result.Unwrap()));
    }

    public static Result<NativeProtocolSession, EcliptixProtocolFailure> CreateFromRoot(
        EcliptixIdentityKeysWrapper identityKeys,
        byte[] rootKey,
        byte[] peerBundle,
        bool isInitiator)
    {
        Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure> result =
            EcliptixProtocolSystemWrapper.CreateFromRoot(identityKeys, rootKey, peerBundle, isInitiator);
        if (result.IsErr)
        {
            return Result<NativeProtocolSession, EcliptixProtocolFailure>.Err(result.UnwrapErr());
        }

        return Result<NativeProtocolSession, EcliptixProtocolFailure>.Ok(new NativeProtocolSession(result.Unwrap()));
    }

    public Result<byte[], EcliptixProtocolFailure> BeginHandshake(uint connectId, byte exchangeType) =>
        _wrapper.BeginHandshake(connectId, exchangeType);

    public Result<byte[], EcliptixProtocolFailure> BeginHandshakeWithPeerKyber(
        uint connectId,
        byte exchangeType,
        byte[] peerKyberPublicKey) =>
        _wrapper.BeginHandshakeWithPeerKyber(connectId, exchangeType, peerKyberPublicKey);

    public Result<Unit, EcliptixProtocolFailure> CompleteHandshake(byte[] peerHandshakeMessage, byte[] rootKey) =>
        _wrapper.CompleteHandshake(peerHandshakeMessage, rootKey);

    public Result<Unit, EcliptixProtocolFailure> CompleteHandshakeAuto(byte[] peerHandshakeMessage) =>
        _wrapper.CompleteHandshakeAuto(peerHandshakeMessage);

    public Result<byte[], EcliptixProtocolFailure> SendMessage(byte[] plaintext) =>
        _wrapper.SendMessage(plaintext);

    public Result<byte[], EcliptixProtocolFailure> ReceiveMessage(byte[] encryptedEnvelope) =>
        _wrapper.ReceiveMessage(encryptedEnvelope);

    public Result<Unit, EcliptixProtocolFailure> ValidateEnvelopeHybridRequirements(byte[] encryptedEnvelope) =>
        EcliptixProtocolSystemWrapper.ValidateEnvelopeHybridRequirements(encryptedEnvelope);

    public Result<byte[], EcliptixProtocolFailure> ExportState() => _wrapper.ExportState();

    public static Result<NativeProtocolSession, EcliptixProtocolFailure> Import(
        EcliptixIdentityKeysWrapper identityKeys,
        byte[] stateBytes)
    {
        Result<EcliptixProtocolSystemWrapper, EcliptixProtocolFailure> importResult =
            EcliptixProtocolSystemWrapper.ImportState(identityKeys, stateBytes);
        if (importResult.IsErr)
        {
            return Result<NativeProtocolSession, EcliptixProtocolFailure>.Err(importResult.UnwrapErr());
        }

        return Result<NativeProtocolSession, EcliptixProtocolFailure>.Ok(
            new NativeProtocolSession(importResult.Unwrap()));
    }

    public EcliptixIdentityKeysWrapper GetIdentityKeys() => _wrapper.GetIdentityKeys();

    public Result<bool, EcliptixProtocolFailure> HasConnection() => _wrapper.HasConnection();

    public Result<uint, EcliptixProtocolFailure> GetConnectionId() => _wrapper.GetConnectionId();

    public Result<(uint SendingIndex, uint ReceivingIndex), EcliptixProtocolFailure> GetChainIndices() =>
        _wrapper.GetChainIndices();

    public Result<Unit, EcliptixProtocolFailure> SetEventHandler(Action<uint>? onProtocolStateChanged) => _wrapper.SetEventHandler(onProtocolStateChanged);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _wrapper.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~NativeProtocolSession()
    {
        Dispose();
    }
}
