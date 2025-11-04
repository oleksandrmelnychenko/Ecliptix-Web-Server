using Akka.Actor;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Infrastructure.Crypto;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Google.Protobuf;

namespace Ecliptix.Core.Infrastructure.SecureChannel;

public class RsaSecureChannelEstablisher(
    IRsaChunkProcessor rsaChunkProcessor,
    CertificatePinningService certificatePinningService,
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
                Task<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>> protocolTask =
                    protocolActor.Ask<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(
                        actorEvent,
                        TimeoutConfiguration.Actor.AskTimeout);
                protocolResult = await protocolTask.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
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

            byte[] encryptedPayload = encryptResult.Unwrap();
            SecureEnvelope responseEnvelope = CreateSecureResponseEnvelope(connectId, encryptedPayload);

            Result<byte[], CertificatePinningFailure> signResult = certificatePinningService.Sign(
                encryptedPayload.AsMemory());

            if (signResult.IsErr)
            {
                return Result<SecureEnvelope, SecureChannelFailure>.Err(
                    SecureChannelFailure.SigningFailed(
                        $"Failed to sign response: {signResult.UnwrapErr().Message}"));
            }

            responseEnvelope.AuthenticationTag = ByteString.CopyFrom(signResult.Unwrap());

            return Result<SecureEnvelope, SecureChannelFailure>.Ok(responseEnvelope);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Result<SecureEnvelope, SecureChannelFailure>.Err(
                SecureChannelFailure.ProtocolError($"Unexpected error: {ex.Message}"));
        }
    }

    private static SecureEnvelope CreateSecureResponseEnvelope(uint connectId, byte[] encryptedPayload)
    {
        EnvelopeMetadata metadata = new()
        {
            EnvelopeId = connectId.ToString(),
            ChannelKeyId = ByteString.Empty,
            Nonce = ByteString.Empty,
            RatchetIndex = 0,
            EnvelopeType = EnvelopeType.Response
        };

        return new SecureEnvelope
        {
            MetaData = metadata.ToByteString(),
            EncryptedPayload = ByteString.CopyFrom(encryptedPayload),
            ResultCode = ByteString.CopyFrom(BitConverter.GetBytes((int)EnvelopeResultCode.Success)),
            Timestamp = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow),
            HeaderNonce = ByteString.Empty,
            DhPublicKey = ByteString.Empty
        };
    }
}
