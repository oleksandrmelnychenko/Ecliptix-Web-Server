using Akka.Actor;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Infrastructure.Builders;
using Ecliptix.Core.Infrastructure.Crypto;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Utilities;
using Google.Protobuf;

namespace Ecliptix.Core.Infrastructure.SecureChannel;

public class RsaSecureChannelEstablisher(
    IRsaChunkProcessor rsaChunkProcessor,
    IActorRef protocolActor)
    : ISecureChannelEstablisher
{
    public async Task<Result<SecureEnvelope, SecureChannelFailure>> EstablishAsync(
        SecureEnvelope request,
        uint connectId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            Result<byte[], CertificatePinningFailure> decryptResult = await rsaChunkProcessor.DecryptChunkedAsync(
                request.EncryptedPayload.Memory,
                cancellationToken);

            if (decryptResult.IsErr)
            {
                return Result<SecureEnvelope, SecureChannelFailure>.Err(
                    SecureChannelFailure.FromCertificateFailure(decryptResult.UnwrapErr()));
            }

            PubKeyExchange pubKeyExchange;
            try
            {
                pubKeyExchange = PubKeyExchange.Parser.ParseFrom(decryptResult.Unwrap());
            }
            catch (Exception ex)
            {
                return Result<SecureEnvelope, SecureChannelFailure>.Err(
                    SecureChannelFailure.InvalidPayload($"Invalid PubKeyExchange format: {ex.Message}"));
            }

            BeginAppDeviceEphemeralConnectActorEvent actorEvent = new(pubKeyExchange, connectId);
            Result<DeriveSharedSecretReply, EcliptixProtocolFailure> protocolResult;

            try
            {
                protocolResult = await protocolActor.Ask<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(
                    actorEvent, cancellationToken);
            }
            catch (Exception ex)
            {
                return Result<SecureEnvelope, SecureChannelFailure>.Err(
                    SecureChannelFailure.ActorCommunicationError($"Protocol actor error: {ex.Message}"));
            }

            if (protocolResult.IsErr)
            {
                EcliptixProtocolFailure failure = protocolResult.UnwrapErr();
                return Result<SecureEnvelope, SecureChannelFailure>.Err(
                    SecureChannelFailure.ProtocolError(failure.Message));
            }

            PubKeyExchange responsePubKeyExchange = protocolResult.Unwrap().PubKeyExchange;
            byte[] responseData = responsePubKeyExchange.ToByteArray();

            Result<byte[], CertificatePinningFailure> encryptResult = await rsaChunkProcessor.EncryptChunkedAsync(
                responseData,
                cancellationToken);

            if (encryptResult.IsErr)
            {
                return Result<SecureEnvelope, SecureChannelFailure>.Err(
                    SecureChannelFailure.FromCertificateFailure(encryptResult.UnwrapErr()));
            }

            SecureEnvelope responseEnvelope = CreateSecureResponseEnvelope(connectId, encryptResult.Unwrap());

            return Result<SecureEnvelope, SecureChannelFailure>.Ok(responseEnvelope);
        }
        catch (Exception ex)
        {
            return Result<SecureEnvelope, SecureChannelFailure>.Err(
                SecureChannelFailure.ProtocolError($"Unexpected error: {ex.Message}"));
        }
    }

    private static SecureEnvelope CreateSecureResponseEnvelope(uint connectId, byte[] encryptedPayload)
    {
        return SecureEnvelopeBuilder
            .CreateResponse(connectId)
            .WithEncryptedPayload(encryptedPayload)
            .Build();
    }
}