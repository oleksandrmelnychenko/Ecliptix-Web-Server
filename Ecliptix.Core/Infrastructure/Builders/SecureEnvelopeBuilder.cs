using Ecliptix.Core.Domain.Protocol.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace Ecliptix.Core.Infrastructure.Builders;

/// <summary>
/// Provides a fluent interface for building SecureEnvelope objects with proper validation and defaults.
/// </summary>
public class SecureEnvelopeBuilder
{
    private uint? _requestId;
    private ByteString? _nonce;
    private uint _ratchetIndex;
    private ByteString? _dhPublicKey;
    private byte[]? _channelKeyId;
    private EnvelopeType _envelopeType = EnvelopeType.Request;
    private string? _correlationId;
    private ByteString? _encryptedPayload;
    private Timestamp? _timestamp;
    private ByteString? _authenticationTag;
    private EnvelopeResultCode _resultCode = EnvelopeResultCode.Success;
    private ByteString? _errorDetails;

    public SecureEnvelopeBuilder WithRequestId(uint requestId)
    {
        _requestId = requestId;
        return this;
    }

    public SecureEnvelopeBuilder WithNonce(ByteString nonce)
    {
        _nonce = nonce;
        return this;
    }

    public SecureEnvelopeBuilder WithNonce(byte[] nonce)
    {
        _nonce = ByteString.CopyFrom(nonce);
        return this;
    }

    public SecureEnvelopeBuilder WithRatchetIndex(uint ratchetIndex)
    {
        _ratchetIndex = ratchetIndex;
        return this;
    }

    public SecureEnvelopeBuilder WithDhPublicKey(ByteString dhPublicKey)
    {
        _dhPublicKey = dhPublicKey;
        return this;
    }

    public SecureEnvelopeBuilder WithDhPublicKey(byte[] dhPublicKey)
    {
        _dhPublicKey = ByteString.CopyFrom(dhPublicKey);
        return this;
    }

    public SecureEnvelopeBuilder WithChannelKeyId(byte[] channelKeyId)
    {
        _channelKeyId = channelKeyId;
        return this;
    }

    public SecureEnvelopeBuilder WithEnvelopeType(EnvelopeType envelopeType)
    {
        _envelopeType = envelopeType;
        return this;
    }

    public SecureEnvelopeBuilder WithCorrelationId(string correlationId)
    {
        _correlationId = correlationId;
        return this;
    }

    public SecureEnvelopeBuilder WithEncryptedPayload(ByteString encryptedPayload)
    {
        _encryptedPayload = encryptedPayload;
        return this;
    }

    public SecureEnvelopeBuilder WithEncryptedPayload(byte[] encryptedPayload)
    {
        _encryptedPayload = ByteString.CopyFrom(encryptedPayload);
        return this;
    }

    public SecureEnvelopeBuilder WithTimestamp(Timestamp timestamp)
    {
        _timestamp = timestamp;
        return this;
    }

    public SecureEnvelopeBuilder WithCurrentTimestamp()
    {
        _timestamp = Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow);
        return this;
    }

    public SecureEnvelopeBuilder WithAuthenticationTag(ByteString authenticationTag)
    {
        _authenticationTag = authenticationTag;
        return this;
    }

    public SecureEnvelopeBuilder WithAuthenticationTag(byte[] authenticationTag)
    {
        _authenticationTag = ByteString.CopyFrom(authenticationTag);
        return this;
    }

    public SecureEnvelopeBuilder WithResultCode(EnvelopeResultCode resultCode)
    {
        _resultCode = resultCode;
        return this;
    }

    public SecureEnvelopeBuilder WithErrorDetails(ByteString errorDetails)
    {
        _errorDetails = errorDetails;
        return this;
    }

    public SecureEnvelopeBuilder WithErrorDetails(string errorMessage)
    {
        _errorDetails = ByteString.CopyFromUtf8(errorMessage);
        return this;
    }

    public SecureEnvelope Build()
    {
        if (!_requestId.HasValue)
            throw new InvalidOperationException("RequestId is required");

        if (_encryptedPayload == null || _encryptedPayload.IsEmpty)
            throw new InvalidOperationException("EncryptedPayload is required");

        var metadata = ProtocolMigrationHelper.CreateEnvelopeMetadata(
            requestId: _requestId.Value,
            nonce: _nonce ?? ByteString.Empty,
            ratchetIndex: _ratchetIndex,
            dhPublicKey: _dhPublicKey,
            channelKeyId: _channelKeyId,
            envelopeType: _envelopeType,
            correlationId: _correlationId
        );

        return ProtocolMigrationHelper.CreateSecureEnvelope(
            metadata: metadata,
            encryptedPayload: _encryptedPayload,
            timestamp: _timestamp,
            authenticationTag: _authenticationTag,
            resultCode: _resultCode,
            errorDetails: _errorDetails
        );
    }

    /// <summary>
    /// Creates a new builder instance for fluent chaining.
    /// </summary>
    public static SecureEnvelopeBuilder Create() => new();

    /// <summary>
    /// Creates a response envelope builder with common response defaults.
    /// </summary>
    public static SecureEnvelopeBuilder CreateResponse(uint requestId)
        => new SecureEnvelopeBuilder()
            .WithRequestId(requestId)
            .WithEnvelopeType(EnvelopeType.Response)
            .WithNonce(ByteString.Empty)
            .WithRatchetIndex(0)
            .WithCurrentTimestamp();

    /// <summary>
    /// Creates a request envelope builder with common request defaults.
    /// </summary>
    public static SecureEnvelopeBuilder CreateRequest(uint requestId)
        => new SecureEnvelopeBuilder()
            .WithRequestId(requestId)
            .WithEnvelopeType(EnvelopeType.Request)
            .WithCurrentTimestamp();
}