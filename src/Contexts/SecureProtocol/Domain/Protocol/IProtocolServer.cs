using Ecliptix.Protobuf.Protocol;
using Ecliptix.SecureProtocol.Domain.ProtocolNative;
using Ecliptix.SharedKernel;

namespace Ecliptix.SecureProtocol.Domain.Protocol;

public interface IProtocolServer : IDisposable
{
    Result<Unit, EcliptixProtocolFailure> Initialize();
    Result<Unit, EcliptixProtocolFailure> Shutdown();

    Result<ProtocolIdentity, EcliptixProtocolFailure> CreateIdentity(byte[]? seed = null, Guid? accountId = null);
    Result<byte[], EcliptixProtocolFailure> GetPublicEd25519(ProtocolIdentity identity);
    Result<byte[], EcliptixProtocolFailure> GetPublicX25519(ProtocolIdentity identity);
    Result<byte[], EcliptixProtocolFailure> GetPublicKyber(ProtocolIdentity identity);

    Result<ProtocolSession, EcliptixProtocolFailure> CreateSession(
        ProtocolIdentity identity,
        Action<uint>? onStateChanged = null);

    Result<ProtocolSession, EcliptixProtocolFailure> CreateSessionFromRoot(
        ProtocolIdentity identity,
        byte[] rootKey,
        byte[] peerBundle,
        bool isInitiator,
        Action<uint>? onStateChanged = null);

    Result<ProtocolSession, EcliptixProtocolFailure> ImportState(
        ProtocolIdentity identity,
        byte[] stateBytes,
        Action<uint>? onStateChanged = null);

    Result<byte[], EcliptixProtocolFailure> BeginHandshake(
        ProtocolSession session,
        uint connectionId,
        PubKeyExchangeType exchangeType,
        byte[] peerKyberPublicKey);

    Result<Unit, EcliptixProtocolFailure> CompleteHandshake(
        ProtocolSession session,
        byte[] peerHandshakeMessage,
        byte[] rootKey);

    Result<Unit, EcliptixProtocolFailure> CompleteHandshakeAuto(
        ProtocolSession session,
        byte[] peerHandshakeMessage);

    Result<byte[], EcliptixProtocolFailure> SendMessage(ProtocolSession session, byte[] plaintext);
    Result<byte[], EcliptixProtocolFailure> ReceiveMessage(ProtocolSession session, byte[] encryptedEnvelope);

    Result<bool, EcliptixProtocolFailure> HasConnection(ProtocolSession session);
    Result<uint, EcliptixProtocolFailure> GetConnectionId(ProtocolSession session);
    Result<uint?, EcliptixProtocolFailure> GetSelectedOpkId(ProtocolSession session);

    Result<byte[], EcliptixProtocolFailure> ExportState(ProtocolSession session);

    Result<Unit, EcliptixProtocolFailure> ValidateEnvelopeHybridRequirements(byte[] encryptedEnvelope);
}

public sealed class ProtocolIdentity : IDisposable
{
    internal ProtocolIdentity(EcliptixIdentityKeys handle)
    {
        Handle = handle;
    }

    internal EcliptixIdentityKeys Handle { get; }

    public bool IsDisposed { get; private set; }

    public void Detach()
    {
        if (IsDisposed)
        {
            return;
        }

        Handle.Detach();
        IsDisposed = true;
        GC.SuppressFinalize(this);
    }

    public void Dispose()
    {
        if (IsDisposed)
        {
            return;
        }

        Handle.Dispose();
        IsDisposed = true;
        GC.SuppressFinalize(this);
    }

    ~ProtocolIdentity()
    {
        Dispose();
    }
}

public sealed class ProtocolSession : IDisposable
{
    internal ProtocolSession(EcliptixProtocolSystem handle)
    {
        Handle = handle;
    }

    internal EcliptixProtocolSystem Handle { get; }

    public bool IsDisposed { get; private set; }

    public void Dispose()
    {
        if (IsDisposed)
        {
            return;
        }

        Handle.Dispose();
        IsDisposed = true;
        GC.SuppressFinalize(this);
    }

    ~ProtocolSession()
    {
        Dispose();
    }
}
