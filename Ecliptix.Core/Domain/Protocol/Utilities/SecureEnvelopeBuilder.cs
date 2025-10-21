using System;
using System.Security.Cryptography;
using Ecliptix.Protobuf.Common;
using Ecliptix.Utilities;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace Ecliptix.Core.Domain.Protocol.Utilities;

public static class SecureEnvelopeBuilder
{
    public static EnvelopeMetadata CreateEnvelopeMetadata(
        uint requestId,
        ByteString nonce,
        uint ratchetIndex,
        byte[]? channelKeyId = null,
        EnvelopeType envelopeType = EnvelopeType.Request,
        string? correlationId = null)
    {
        EnvelopeMetadata metadata = new()
        {
            EnvelopeId = requestId.ToString(),
            Nonce = nonce,
            RatchetIndex = ratchetIndex,
            EnvelopeType = envelopeType
        };

        if (channelKeyId != null && channelKeyId.Length > 0)
        {
            metadata.ChannelKeyId = ByteString.CopyFrom(channelKeyId);
        }
        else
        {
            metadata.ChannelKeyId = GenerateChannelKeyId();
        }

        if (!string.IsNullOrEmpty(correlationId))
        {
            metadata.CorrelationId = correlationId;
        }

        return metadata;
    }

    public static SecureEnvelope CreateSecureEnvelope(
        EnvelopeMetadata metadata,
        ByteString encryptedPayload,
        Timestamp? timestamp = null,
        ByteString? authenticationTag = null,
        EnvelopeResultCode resultCode = EnvelopeResultCode.Success,
        ByteString? errorDetails = null,
        ByteString? headerNonce = null,
        ByteString? dhPublicKey = null)
    {
        SecureEnvelope envelope = new()
        {
            MetaData = metadata.ToByteString(),
            EncryptedPayload = encryptedPayload,
            ResultCode = ByteString.CopyFrom(BitConverter.GetBytes((int)resultCode)),
            Timestamp = timestamp ?? Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow),
            HeaderNonce = headerNonce ?? ByteString.Empty,
            DhPublicKey = dhPublicKey ?? ByteString.Empty
        };

        if (authenticationTag != null && !authenticationTag.IsEmpty)
        {
            envelope.AuthenticationTag = authenticationTag;
        }

        if (errorDetails != null && !errorDetails.IsEmpty)
        {
            envelope.ErrorDetails = errorDetails;
        }

        return envelope;
    }

    private static ByteString GenerateChannelKeyId()
    {
        byte[] keyId = new byte[16];
        RandomNumberGenerator.Fill(keyId);
        return ByteString.CopyFrom(keyId);
    }

    public static Result<byte[], EcliptixProtocolFailure> EncryptMetadata(
        EnvelopeMetadata metadata,
        byte[] headerEncryptionKey,
        byte[] headerNonce,
        byte[] associatedData)
    {
        byte[]? metadataBytes = null;
        byte[]? ciphertext = null;
        byte[]? tag = null;
        try
        {
            metadataBytes = metadata.ToByteArray();

            ciphertext = new byte[metadataBytes.Length];
            tag = new byte[Constants.AesGcmTagSize];

            using (AesGcm aesGcm =
                new(headerEncryptionKey, Constants.AesGcmTagSize))
            {
                aesGcm.Encrypt(headerNonce, metadataBytes, ciphertext, tag, associatedData);
            }

            byte[] result = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);

            return Result<byte[], EcliptixProtocolFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            return Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to encrypt metadata", ex));
        }
        finally
        {
            if (metadataBytes != null)
            {
                SodiumInterop.SecureWipe(metadataBytes);
            }

            if (ciphertext != null)
            {
                SodiumInterop.SecureWipe(ciphertext);
            }

            if (tag != null)
            {
                SodiumInterop.SecureWipe(tag);
            }
        }
    }

    public static Result<EnvelopeMetadata, EcliptixProtocolFailure> DecryptMetadata(
        byte[] encryptedMetadata,
        byte[] headerEncryptionKey,
        byte[] headerNonce,
        byte[] associatedData)
    {
        byte[]? plaintext = null;
        try
        {
            int cipherLength = encryptedMetadata.Length - Constants.AesGcmTagSize;
            if (cipherLength < 0)
            {
                return Result<EnvelopeMetadata, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.BufferTooSmall("Encrypted metadata too small"));
            }

            ReadOnlySpan<byte> ciphertextSpan = encryptedMetadata.AsSpan(0, cipherLength);
            ReadOnlySpan<byte> tagSpan = encryptedMetadata.AsSpan(cipherLength);

            plaintext = new byte[cipherLength];

            using (AesGcm aesGcm =
                new(headerEncryptionKey, Constants.AesGcmTagSize))
            {
                aesGcm.Decrypt(headerNonce, ciphertextSpan, tagSpan, plaintext, associatedData);
            }

            EnvelopeMetadata metadata = EnvelopeMetadata.Parser.ParseFrom(plaintext);
            return Result<EnvelopeMetadata, EcliptixProtocolFailure>.Ok(metadata);
        }
        catch (CryptographicException cryptoEx)
        {
            return Result<EnvelopeMetadata, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.HeaderAuthFailed("Header authentication failed", cryptoEx));
        }
        catch (Exception ex)
        {
            return Result<EnvelopeMetadata, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to decrypt metadata", ex));
        }
        finally
        {
            if (plaintext != null)
            {
                SodiumInterop.SecureWipe(plaintext);
            }
        }
    }
}
