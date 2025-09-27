using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Domain.Protocol.Utilities;
using Ecliptix.Domain.Abstractions;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Google.Protobuf;
using Grpc.Core;
using Serilog;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;

public class GrpcCipherService(IEcliptixActorRegistry actorRegistry, ISessionKeyService sessionKeyService) : IGrpcCipherService
{
    private readonly IActorRef _protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);

    private static PubKeyExchangeType GetExchangeTypeFromMetadata(ServerCallContext context)
    {
        string connectionContextId = GrpcMetadataHandler.GetConnectionContextId(context.RequestHeaders);

        if (Enum.TryParse(connectionContextId, true, out PubKeyExchangeType exchangeType) &&
            Enum.IsDefined(exchangeType))
        {
            return exchangeType;
        }

        return PubKeyExchangeType.DataCenterEphemeralConnect;
    }

    public async Task<Result<SecureEnvelope, FailureBase>> EncryptPayload(byte[] payload, uint connectId,
        ServerCallContext context)
    {
        try
        {
            PubKeyExchangeType exchangeType = GetExchangeTypeFromMetadata(context);

            Result<(EnvelopeMetadata Metadata, byte[] EncryptedPayload), EcliptixProtocolFailure> componentsResult =
                await GetEncryptedComponents(payload, connectId, exchangeType, context);

            if (componentsResult.IsErr)
            {
                return Result<SecureEnvelope, FailureBase>.Err(componentsResult.UnwrapErr());
            }

            (EnvelopeMetadata metadata, byte[] encryptedPayload) = componentsResult.Unwrap();

            Result<byte[], string> sessionKeyResult = await sessionKeyService.GetSessionKeyAsync(connectId);

            if (sessionKeyResult.IsOk)
            {
                byte[] sessionKey = sessionKeyResult.Unwrap();

                /*
                if (sessionKey.Length != 32)
                {
                    return Result<SecureEnvelope, FailureBase>.Err(
                        new EcliptixProtocolFailure(EcliptixProtocolFailureType.StateMissing, "Invalid session key length"));
                }*/

                /*Result<byte[], string> encryptedHeaderResult = EncryptHeader(metadata, sessionKey);

                CryptographicOperations.ZeroMemory(sessionKey);

                if (encryptedHeaderResult.IsErr)
                {
                    return Result<SecureEnvelope, FailureBase>.Err(
                        new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, "Header encryption failed"));
                }*/

                SecureEnvelope dualLayerPayload = new()
                {
                    MetaData = ByteString.CopyFrom(metadata.ToByteArray()),
                    EncryptedPayload = ByteString.CopyFrom(encryptedPayload),
                    Timestamp = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(DateTime.UtcNow)
                };

                return Result<SecureEnvelope, FailureBase>.Ok(dualLayerPayload);
            }

            SecureEnvelope protocolOnlyPayload = ProtocolMigrationHelper.CreateSecureEnvelope(
                metadata,
                ByteString.CopyFrom(encryptedPayload),
                Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(DateTime.UtcNow));

            return Result<SecureEnvelope, FailureBase>.Ok(protocolOnlyPayload);
        }
        catch (Exception ex)
        {
            return Result<SecureEnvelope, FailureBase>.Err(
                new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, "Dual-layer encryption failed"));
        }
    }

    public async Task<Result<byte[], FailureBase>> DecryptPayload(SecureEnvelope request, uint connectId,
        ServerCallContext context)
    {
        try
        {
            Result<byte[], string> sessionKeyResult = await sessionKeyService.GetSessionKeyAsync(connectId);
            //EnvelopeMetadata decryptedHeader;
            Result<EnvelopeMetadata, EcliptixProtocolFailure> metadataResult = ProtocolMigrationHelper.ParseEnvelopeMetadata(request.MetaData);
            /*f (sessionKeyResult.IsOk)
            {
                byte[] sessionKey = sessionKeyResult.Unwrap();
                /*Result<EnvelopeMetadata, string> headerDecryptResult = DecryptHeaderWithKey(request.MetaData.ToByteArray(), sessionKey);

                if (headerDecryptResult.IsErr)
                {
                    Log.Error("🔒 Failed to decrypt header with session key for connectId {ConnectId}: {Error}",
                        connectId, headerDecryptResult.UnwrapErr());
                    return Result<byte[], FailureBase>.Err(
                        new EcliptixProtocolFailure(EcliptixProtocolFailureType.StateMissing, "Header decryption failed"));
                }#1#

                decryptedHeader = headerDecryptResult.Unwrap();
                Log.Debug("🔒 Using dual-layer decryption (protocol + session key) for connectId {ConnectId}", connectId);
            }
            else
            {
                Result<EnvelopeMetadata, EcliptixProtocolFailure> metadataResult = ProtocolMigrationHelper.ParseEnvelopeMetadata(request.MetaData);
                if (metadataResult.IsErr)
                {
                    Log.Warning("🔒 Failed to parse metadata for protocol-only decryption, connectId {ConnectId}: {Error}",
                        connectId, metadataResult.UnwrapErr().Message);
                    return Result<byte[], FailureBase>.Err(metadataResult.UnwrapErr());
                }

                decryptedHeader = metadataResult.Unwrap();
                Log.Debug("🔒 Using protocol-only decryption (no session key) for connectId {ConnectId}", connectId);
            }
            */

            PubKeyExchangeType exchangeType = GetExchangeTypeFromMetadata(context);

            Result<byte[], EcliptixProtocolFailure> decryptionResult =
                await DecryptPayloadWithHeader(request.EncryptedPayload.ToByteArray(), metadataResult.Unwrap(), connectId, exchangeType, context);

            return decryptionResult.IsErr
                ? Result<byte[], FailureBase>.Err(decryptionResult.UnwrapErr())
                : Result<byte[], FailureBase>.Ok(decryptionResult.Unwrap());
        }
        catch (Exception ex)
        {
            Log.Error(ex, "🔒 Unexpected error during payload decryption for connectId {ConnectId}", connectId);
            return Result<byte[], FailureBase>.Err(
                new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, "Payload decryption failed"));
        }
    }

    public async Task<SecureEnvelope> CreateFailureResponse(FailureBase failure, uint connectId,
        ServerCallContext context)
    {
        context.Status = failure.ToGrpcStatus();
        Result<SecureEnvelope, FailureBase> encryptResult = await EncryptPayload([], connectId, context);
        return encryptResult.IsErr ? new SecureEnvelope() : encryptResult.Unwrap();
    }

    private async Task<Result<(EnvelopeMetadata Metadata, byte[] EncryptedPayload), EcliptixProtocolFailure>> GetEncryptedComponents(
        byte[] payload, uint connectId, PubKeyExchangeType exchangeType, ServerCallContext context)
    {
        EncryptPayloadComponentsActorEvent encryptCommand = new(exchangeType, payload);
        ForwardToConnectActorEvent encryptForwarder = new(connectId, encryptCommand);

        Result<(EnvelopeMetadata Metadata, byte[] EncryptedPayload), EcliptixProtocolFailure> result =
            await _protocolActor.Ask<Result<(EnvelopeMetadata Metadata, byte[] EncryptedPayload), EcliptixProtocolFailure>>(
                encryptForwarder, context.CancellationToken);

        return result;
    }

    private async Task<Result<byte[], EcliptixProtocolFailure>> DecryptPayloadWithHeader(
        byte[] encryptedPayload, EnvelopeMetadata metadata, uint connectId, PubKeyExchangeType exchangeType, ServerCallContext context)
    {
        DecryptPayloadWithHeaderActorEvent decryptCommand = new(exchangeType, metadata, encryptedPayload);
        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptCommand);

        Result<byte[], EcliptixProtocolFailure> result =
            await _protocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(
                decryptForwarder, context.CancellationToken);

        return result;
    }

    private static Result<byte[], string> EncryptHeader(EnvelopeMetadata metadata, byte[] sessionKey)
    {
        try
        {
            byte[] headerBytes = metadata.ToByteArray();
            byte[] nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);

            using AesGcm aes = new(sessionKey, 16);
            byte[] ciphertext = new byte[headerBytes.Length];
            byte[] tag = new byte[16];

            aes.Encrypt(nonce, headerBytes, ciphertext, tag);

            byte[] result = new byte[12 + 16 + ciphertext.Length];
            Array.Copy(nonce, 0, result, 0, 12);
            Array.Copy(tag, 0, result, 12, 16);
            Array.Copy(ciphertext, 0, result, 28, ciphertext.Length);

            return Result<byte[], string>.Ok(result);
        }
        catch (Exception ex)
        {
            return Result<byte[], string>.Err($"Header encryption failed: {ex.Message}");
        }
    }

    private async Task<Result<EnvelopeMetadata, string>> DecryptHeader(byte[] encryptedHeader, uint connectId)
    {
        Result<byte[], string> sessionKeyResult = await sessionKeyService.GetSessionKeyAsync(connectId);
        if (sessionKeyResult.IsErr)
        {
            return Result<EnvelopeMetadata, string>.Err($"Session key not found for connectId {connectId}: {sessionKeyResult.UnwrapErr()}");
        }

        byte[] sessionKey = sessionKeyResult.Unwrap();
        return DecryptHeaderWithKey(encryptedHeader, sessionKey);
    }

    private static Result<EnvelopeMetadata, string> DecryptHeaderWithKey(byte[] encryptedHeader, byte[] sessionKey)
    {
        try
        {
            if (encryptedHeader.Length < 28)
            {
                return Result<EnvelopeMetadata, string>.Err("Invalid encrypted header format. Expected at least 28 bytes for AES-GCM.");
            }

            if (sessionKey.Length != 32)
            {
                return Result<EnvelopeMetadata, string>.Err("Invalid session key length. Expected 32 bytes for AES-256.");
            }

            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[encryptedHeader.Length - 28];

            Array.Copy(encryptedHeader, 0, nonce, 0, 12);
            Array.Copy(encryptedHeader, 12, tag, 0, 16);
            Array.Copy(encryptedHeader, 28, ciphertext, 0, ciphertext.Length);

            using AesGcm aes = new(sessionKey, 16);
            byte[] plaintext = new byte[ciphertext.Length];

            aes.Decrypt(nonce, ciphertext, tag, plaintext);

            CryptographicOperations.ZeroMemory(sessionKey);

            EnvelopeMetadata metadata = EnvelopeMetadata.Parser.ParseFrom(plaintext);
            CryptographicOperations.ZeroMemory(plaintext);

            return Result<EnvelopeMetadata, string>.Ok(metadata);
        }
        catch (CryptographicException cryptoEx)
        {
            return Result<EnvelopeMetadata, string>.Err($"Cryptographic error during header decryption: {cryptoEx.Message}");
        }
        catch (InvalidProtocolBufferException protoEx)
        {
            return Result<EnvelopeMetadata, string>.Err($"Failed to parse decrypted header as EnvelopeMetadata: {protoEx.Message}");
        }
        catch (Exception ex)
        {
            return Result<EnvelopeMetadata, string>.Err($"Header decryption failed: {ex.Message}");
        }
    }
}