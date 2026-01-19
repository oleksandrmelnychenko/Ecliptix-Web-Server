using Akka.Actor;
using Ecliptix.Security.Certificate.Pinning.Crypto;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Serilog;
using System.Buffers;
using System.IO;

namespace Ecliptix.Security.Certificate.Pinning.SecureChannel;

public class RsaSecureChannelEstablisher(
    IRsaChunkProcessor rsaChunkProcessor,
    CertificatePinningService certificatePinningService,
    IActorRef protocolActor)
    : ISecureChannelEstablisher
{
    public async Task<Result<SecureEnvelope, SecureChannelFailure>> EstablishAsync(
        SecureEnvelope request,
        uint connectId,
        PubKeyExchangeType exchangeType,
        CancellationToken cancellationToken = default)
    {
        try
        {
            Result<byte[], CertificatePinningFailure> decryptResult = await rsaChunkProcessor.DecryptChunkedAsync(
                request.EncryptedPayload.Memory,
                cancellationToken);

            if (decryptResult.IsErr)
            {
                CertificatePinningFailure failure = decryptResult.UnwrapErr();
                return Result<SecureEnvelope, SecureChannelFailure>.Err(
                    SecureChannelFailure.FromCertificateFailure(failure));
            }

            byte[] handshakeInit = decryptResult.Unwrap();

            Log.Information(
                "[RsaSecureChannelEstablisher] Parsed handshake init. ConnectId={ConnectId}, ExchangeType={ExchangeType}, PayloadSize={PayloadSize}",
                connectId, exchangeType, handshakeInit.Length);

            InitiateEphemeralConnectCommand actorEvent = new(exchangeType, handshakeInit, connectId);
            Result<DeriveSharedSecretResponse, EcliptixProtocolFailure> protocolResult;

            try
            {
                Task<Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>> protocolTask =
                    protocolActor.Ask<Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>>(
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

            byte[] handshakeAck = protocolResult.Unwrap().HandshakeAck;
            byte[]? responseBuffer = null;
            int responseSize = 0;

            try
            {
                responseSize = handshakeAck.Length;
                responseBuffer = ArrayPool<byte>.Shared.Rent(responseSize);

                Buffer.BlockCopy(handshakeAck, 0, responseBuffer, 0, responseSize);

                ReadOnlyMemory<byte> responseMemory = new(responseBuffer, 0, responseSize);
                Result<byte[], CertificatePinningFailure> encryptResult =
                    await rsaChunkProcessor.EncryptChunkedAsync(responseMemory, cancellationToken);

                if (encryptResult.IsErr)
                {
                    CertificatePinningFailure encryptFailure = encryptResult.UnwrapErr();
                    return Result<SecureEnvelope, SecureChannelFailure>.Err(
                        SecureChannelFailure.FromCertificateFailure(encryptFailure));
                }

                Result<byte[], CertificatePinningFailure> signResult =
                    certificatePinningService.Sign(encryptResult.Unwrap());

                if (signResult.IsErr)
                {
                    CertificatePinningFailure signFailure = signResult.UnwrapErr();
                    return Result<SecureEnvelope, SecureChannelFailure>.Err(
                        SecureChannelFailure.FromCertificateFailure(signFailure));
                }

                SecureEnvelope responseEnvelope = new()
                {
                    Version = 1,
                    EncryptedPayload = ByteString.CopyFrom(encryptResult.Unwrap()),
                    EncryptedMetadata = ByteString.CopyFrom(signResult.Unwrap()),
                    HeaderNonce = ByteString.Empty,
                    RatchetEpoch = 0,
                    SentAt = Timestamp.FromDateTime(DateTime.UtcNow)
                };

                return Result<SecureEnvelope, SecureChannelFailure>.Ok(responseEnvelope);
            }
            finally
            {
                if (responseBuffer != null && responseSize > 0)
                {
                    ArrayPool<byte>.Shared.Return(responseBuffer);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Result<SecureEnvelope, SecureChannelFailure>.Err(
                SecureChannelFailure.ActorCommunicationError($"Unexpected error during channel establishment: {ex.Message}"));
        }
    }
}
