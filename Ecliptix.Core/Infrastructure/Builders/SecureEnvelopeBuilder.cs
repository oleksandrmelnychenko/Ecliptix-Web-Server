using Ecliptix.Core.Domain.Protocol.Utilities;
using Ecliptix.Protobuf.Common;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace Ecliptix.Core.Infrastructure.Builders;

public class SecureEnvelopeBuilder
{
    private uint? _requestId;
    private ByteString? _nonce;
    private uint _ratchetIndex;
    private EnvelopeType _envelopeType = EnvelopeType.Request;
    private ByteString? _encryptedPayload;
    private Timestamp? _timestamp;

    private SecureEnvelopeBuilder WithRequestId(uint requestId)
    {
        _requestId = requestId;
        return this;
    }

    private SecureEnvelopeBuilder WithNonce(ByteString nonce)
    {
        _nonce = nonce;
        return this;
    }

    private SecureEnvelopeBuilder WithRatchetIndex(uint ratchetIndex)
    {
        _ratchetIndex = ratchetIndex;
        return this;
    }

    private SecureEnvelopeBuilder WithEnvelopeType(EnvelopeType envelopeType)
    {
        _envelopeType = envelopeType;
        return this;
    }

    public SecureEnvelopeBuilder WithEncryptedPayload(byte[] encryptedPayload)
    {
        _encryptedPayload = ByteString.CopyFrom(encryptedPayload);
        return this;
    }

    private SecureEnvelopeBuilder WithCurrentTimestamp()
    {
        _timestamp = Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow);
        return this;
    }

    public SecureEnvelope Build()
    {
        if (!_requestId.HasValue)
            throw new InvalidOperationException("RequestId is required");

        if (_encryptedPayload == null || _encryptedPayload.IsEmpty)
            throw new InvalidOperationException("EncryptedPayload is required");

        EnvelopeMetadata metadata = ProtocolMigrationHelper.CreateEnvelopeMetadata(
            requestId: _requestId.Value,
            nonce: _nonce ?? ByteString.Empty,
            ratchetIndex: _ratchetIndex,
            envelopeType: _envelopeType
        );

        return ProtocolMigrationHelper.CreateSecureEnvelope(
            metadata: metadata,
            encryptedPayload: _encryptedPayload,
            timestamp: _timestamp
        );
    }

    public static SecureEnvelopeBuilder CreateResponse(uint requestId)
        => new SecureEnvelopeBuilder()
            .WithRequestId(requestId)
            .WithEnvelopeType(EnvelopeType.Response)
            .WithNonce(ByteString.Empty)
            .WithRatchetIndex(0)
            .WithCurrentTimestamp();
}