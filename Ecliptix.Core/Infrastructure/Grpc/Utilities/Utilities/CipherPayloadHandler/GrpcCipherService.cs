using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Domain.Abstractions;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Google.Protobuf;
using Grpc.Core;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
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

    public async Task<Result<CipherPayload, FailureBase>> EncryptPayload(byte[] payload, uint connectId,
        ServerCallContext context)
    {
        try
        {
            PubKeyExchangeType exchangeType = GetExchangeTypeFromMetadata(context);

            Result<(CipherHeader Header, byte[] EncryptedPayload), EcliptixProtocolFailure> componentsResult =
                await GetEncryptedComponents(payload, connectId, exchangeType, context);

            if (componentsResult.IsErr)
            {
                return Result<CipherPayload, FailureBase>.Err(componentsResult.UnwrapErr());
            }

            (CipherHeader header, byte[] encryptedPayload) = componentsResult.Unwrap();

            // Check if we have a session key to determine encryption strategy
            Result<byte[], string> sessionKeyResult = await sessionKeyService.GetSessionKeyAsync(connectId);

            if (sessionKeyResult.IsOk)
            {
                // We have a session key - use dual-layer encryption (encrypt header with session key)
                byte[] sessionKey = sessionKeyResult.Unwrap();

                if (sessionKey.Length != 32)
                {
                    return Result<CipherPayload, FailureBase>.Err(
                        new EcliptixProtocolFailure(EcliptixProtocolFailureType.StateMissing, "Invalid session key length"));
                }

                Result<byte[], string> encryptedHeaderResult = EncryptHeader(header, sessionKey);

                CryptographicOperations.ZeroMemory(sessionKey);

                if (encryptedHeaderResult.IsErr)
                {
                    return Result<CipherPayload, FailureBase>.Err(
                        new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, "Header encryption failed"));
                }

                CipherPayload dualLayerPayload = new()
                {
                    Header = ByteString.CopyFrom(encryptedHeaderResult.Unwrap()),
                    Payload = ByteString.CopyFrom(encryptedPayload),
                    CreatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(DateTime.UtcNow)
                };

                Log.Debug("🔒 Using dual-layer encryption (protocol + session key) for connectId {ConnectId}", connectId);
                return Result<CipherPayload, FailureBase>.Ok(dualLayerPayload);
            }
            else
            {
                // No session key - use protocol-only encryption (header is not encrypted)
                CipherPayload protocolOnlyPayload = new()
                {
                    Header = ByteString.CopyFrom(header.ToByteArray()),
                    Payload = ByteString.CopyFrom(encryptedPayload),
                    CreatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(DateTime.UtcNow)
                };

                Log.Debug("🔒 Using protocol-only encryption (no session key) for connectId {ConnectId}", connectId);
                return Result<CipherPayload, FailureBase>.Ok(protocolOnlyPayload);
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "🔒 Unexpected error during dual-layer encryption for connectId {ConnectId}", connectId);
            return Result<CipherPayload, FailureBase>.Err(
                new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, "Dual-layer encryption failed"));
        }
    }

    public async Task<Result<byte[], FailureBase>> DecryptPayload(CipherPayload request, uint connectId,
        ServerCallContext context)
    {
        try
        {
            // First check if we have a session key to determine decryption strategy
            Result<byte[], string> sessionKeyResult = await sessionKeyService.GetSessionKeyAsync(connectId);
            CipherHeader decryptedHeader;

            if (sessionKeyResult.IsOk)
            {
                // We have a session key - use dual-layer decryption (decrypt header with session key)
                byte[] sessionKey = sessionKeyResult.Unwrap();
                Result<CipherHeader, string> headerDecryptResult = DecryptHeaderWithKey(request.Header.ToByteArray(), sessionKey);

                if (headerDecryptResult.IsErr)
                {
                    Log.Error("🔒 Failed to decrypt header with session key for connectId {ConnectId}: {Error}",
                        connectId, headerDecryptResult.UnwrapErr());
                    return Result<byte[], FailureBase>.Err(
                        new EcliptixProtocolFailure(EcliptixProtocolFailureType.StateMissing, "Header decryption failed"));
                }

                decryptedHeader = headerDecryptResult.Unwrap();
                Log.Debug("🔒 Using dual-layer decryption (protocol + session key) for connectId {ConnectId}", connectId);
            }
            else
            {
                // No session key - use protocol-only decryption (header is not encrypted)
                try
                {
                    decryptedHeader = CipherHeader.Parser.ParseFrom(request.Header);
                    Log.Debug("🔒 Using protocol-only decryption (no session key) for connectId {ConnectId}", connectId);
                }
                catch (Exception ex)
                {
                    Log.Warning("🔒 Failed to parse header for protocol-only decryption, connectId {ConnectId}: {Error}",
                        connectId, ex.Message);
                    return Result<byte[], FailureBase>.Err(
                        new EcliptixProtocolFailure(EcliptixProtocolFailureType.StateMissing, "Header parsing failed"));
                }
            }

            PubKeyExchangeType exchangeType = GetExchangeTypeFromMetadata(context);

            Result<byte[], EcliptixProtocolFailure> decryptionResult =
                await DecryptPayloadWithHeader(request.Payload.ToByteArray(), decryptedHeader, connectId, exchangeType, context);

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

    public async Task<CipherPayload> CreateFailureResponse(FailureBase failure, uint connectId,
        ServerCallContext context)
    {
        context.Status = failure.ToGrpcStatus();
        Result<CipherPayload, FailureBase> encryptResult = await EncryptPayload([], connectId, context);
        return encryptResult.IsErr ? new CipherPayload() : encryptResult.Unwrap();
    }

    private async Task<Result<(CipherHeader Header, byte[] EncryptedPayload), EcliptixProtocolFailure>> GetEncryptedComponents(
        byte[] payload, uint connectId, PubKeyExchangeType exchangeType, ServerCallContext context)
    {
        EncryptPayloadComponentsActorEvent encryptCommand = new(exchangeType, payload);
        ForwardToConnectActorEvent encryptForwarder = new(connectId, encryptCommand);

        Result<(CipherHeader Header, byte[] EncryptedPayload), EcliptixProtocolFailure> result =
            await _protocolActor.Ask<Result<(CipherHeader Header, byte[] EncryptedPayload), EcliptixProtocolFailure>>(
                encryptForwarder, context.CancellationToken);

        return result;
    }

    private async Task<Result<byte[], EcliptixProtocolFailure>> DecryptPayloadWithHeader(
        byte[] encryptedPayload, CipherHeader header, uint connectId, PubKeyExchangeType exchangeType, ServerCallContext context)
    {
        DecryptPayloadWithHeaderActorEvent decryptCommand = new(exchangeType, header, encryptedPayload);
        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptCommand);

        Result<byte[], EcliptixProtocolFailure> result =
            await _protocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(
                decryptForwarder, context.CancellationToken);

        return result;
    }

    private static Result<byte[], string> EncryptHeader(CipherHeader header, byte[] sessionKey)
    {
        try
        {
            byte[] headerBytes = header.ToByteArray();
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

    private async Task<Result<CipherHeader, string>> DecryptHeader(byte[] encryptedHeader, uint connectId)
    {
        Result<byte[], string> sessionKeyResult = await sessionKeyService.GetSessionKeyAsync(connectId);
        if (sessionKeyResult.IsErr)
        {
            return Result<CipherHeader, string>.Err($"Session key not found for connectId {connectId}: {sessionKeyResult.UnwrapErr()}");
        }

        byte[] sessionKey = sessionKeyResult.Unwrap();
        return DecryptHeaderWithKey(encryptedHeader, sessionKey);
    }

    private static Result<CipherHeader, string> DecryptHeaderWithKey(byte[] encryptedHeader, byte[] sessionKey)
    {
        try
        {
            if (encryptedHeader.Length < 28)
            {
                return Result<CipherHeader, string>.Err("Invalid encrypted header format. Expected at least 28 bytes for AES-GCM.");
            }

            if (sessionKey.Length != 32)
            {
                return Result<CipherHeader, string>.Err("Invalid session key length. Expected 32 bytes for AES-256.");
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

            CipherHeader header = CipherHeader.Parser.ParseFrom(plaintext);
            CryptographicOperations.ZeroMemory(plaintext);

            return Result<CipherHeader, string>.Ok(header);
        }
        catch (CryptographicException cryptoEx)
        {
            return Result<CipherHeader, string>.Err($"Cryptographic error during header decryption: {cryptoEx.Message}");
        }
        catch (InvalidProtocolBufferException protoEx)
        {
            return Result<CipherHeader, string>.Err($"Failed to parse decrypted header as CipherHeader: {protoEx.Message}");
        }
        catch (Exception ex)
        {
            return Result<CipherHeader, string>.Err($"Header decryption failed: {ex.Message}");
        }
    }
}