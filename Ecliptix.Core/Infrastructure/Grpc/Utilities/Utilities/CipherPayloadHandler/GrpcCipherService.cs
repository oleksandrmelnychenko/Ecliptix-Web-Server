using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Domain.Protocol.Utilities;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Google.Protobuf;
using Grpc.Core;
using Serilog;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;

public class GrpcCipherService(IEcliptixActorRegistry actorRegistry) : IGrpcCipherService
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

            // Use EncryptPayloadActorEvent to get a complete SecureEnvelope with encrypted metadata and HeaderNonce
            EncryptPayloadActorEvent encryptCommand = new(exchangeType, payload);
            ForwardToConnectActorEvent encryptForwarder = new(connectId, encryptCommand);

            Result<SecureEnvelope, EcliptixProtocolFailure> result =
                await _protocolActor.Ask<Result<SecureEnvelope, EcliptixProtocolFailure>>(
                    encryptForwarder, context.CancellationToken);

            return result.IsErr
                ? Result<SecureEnvelope, FailureBase>.Err(result.UnwrapErr())
                : Result<SecureEnvelope, FailureBase>.Ok(result.Unwrap());
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Payload encryption failed for connectId {ConnectId}", connectId);
            return Result<SecureEnvelope, FailureBase>.Err(
                new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, "Payload encryption failed"));
        }
    }

    public async Task<Result<byte[], FailureBase>> DecryptPayload(SecureEnvelope request, uint connectId,
        ServerCallContext context)
    {
        try
        {
            PubKeyExchangeType exchangeType = GetExchangeTypeFromMetadata(context);

            DecryptSecureEnvelopeActorEvent decryptCommand = new(exchangeType, request);
            ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptCommand);

            Result<byte[], EcliptixProtocolFailure> decryptionResult =
                await _protocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(
                    decryptForwarder, context.CancellationToken);

            return decryptionResult.IsErr
                ? Result<byte[], FailureBase>.Err(decryptionResult.UnwrapErr())
                : Result<byte[], FailureBase>.Ok(decryptionResult.Unwrap());
        }
        catch (Exception ex)
        {

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
        return Result<EnvelopeMetadata, string>.Err($"Session key service removed - header decryption not available");
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