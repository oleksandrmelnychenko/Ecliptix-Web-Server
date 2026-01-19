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
    Result<byte[], EcliptixProtocolFailure> CreatePreKeyBundle(ProtocolIdentity identity);

    Result<ProtocolHandshakeResponderStart, EcliptixProtocolFailure> StartHandshakeResponder(
        ProtocolIdentity identity,
        byte[] localPreKeyBundle,
        byte[] handshakeInit,
        uint maxMessagesPerChain);

    Result<ProtocolSession, EcliptixProtocolFailure> FinishHandshakeResponder(
        ProtocolHandshakeResponder responder);

    Result<byte[], EcliptixProtocolFailure> Encrypt(
        ProtocolSession session,
        byte[] plaintext,
        EnvelopeType envelopeType,
        uint envelopeId,
        string? correlationId = null);

    Result<ProtocolDecryptResult, EcliptixProtocolFailure> Decrypt(
        ProtocolSession session,
        byte[] encryptedEnvelope);

    Result<byte[], EcliptixProtocolFailure> ExportState(ProtocolSession session);
    Result<ProtocolSession, EcliptixProtocolFailure> ImportState(byte[] stateBytes);

    Result<Unit, EcliptixProtocolFailure> ValidateEnvelope(byte[] encryptedEnvelope);
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
    internal ProtocolSession(EcliptixSession handle)
    {
        Handle = handle;
    }

    internal EcliptixSession Handle { get; }

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

public sealed class ProtocolHandshakeResponder : IDisposable
{
    internal ProtocolHandshakeResponder(HandshakeResponder handle)
    {
        Handle = handle;
    }

    internal HandshakeResponder Handle { get; }

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

    ~ProtocolHandshakeResponder()
    {
        Dispose();
    }
}

public sealed class ProtocolHandshakeResponderStart
{
    public ProtocolHandshakeResponder Responder { get; }
    public byte[] HandshakeAck { get; }

    internal ProtocolHandshakeResponderStart(ProtocolHandshakeResponder responder, byte[] handshakeAck)
    {
        Responder = responder;
        HandshakeAck = handshakeAck;
    }
}

public sealed class ProtocolDecryptResult
{
    public byte[] Plaintext { get; }
    public byte[] Metadata { get; }

    internal ProtocolDecryptResult(byte[] plaintext, byte[] metadata)
    {
        Plaintext = plaintext;
        Metadata = metadata;
    }
}
