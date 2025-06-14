using System.Threading.Channels;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Memberships;

public class VerificationFlowServices(
    IActorRegistry actorRegistry,
    IPhoneNumberValidator phoneNumberValidator,
    ILogger<VerificationFlowServices> logger)
    : VerificationFlowServicesBase(actorRegistry, logger)
{
    public override async Task InitiateVerification(CipherPayload request,
        IServerStreamWriter<CipherPayload> responseStream,
        ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptionResult = await DecryptRequest(request, context);
        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        InitiateVerificationRequest initiateRequest =
            Helpers.ParseFromBytes<InitiateVerificationRequest>(decryptionResult.Unwrap());
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Channel<Result<VerificationCountdownUpdate, VerificationFlowFailure>> channel =
            Channel.CreateUnbounded<Result<VerificationCountdownUpdate, VerificationFlowFailure>>();
        ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> writer = channel.Writer;

        Task streamingTask = StreamCountdownUpdatesAsync(responseStream, channel.Reader, context);
        context.CancellationToken.Register(() => StopVerificationFlowActor(context, connectId));

        Result<Unit, VerificationFlowFailure> initiationResult = await VerificationFlowManagerActor
            .Ask<Result<Unit, VerificationFlowFailure>>(new InitiateVerificationFlowActorEvent(
                connectId,
                Helpers.FromByteStringToGuid(initiateRequest.PhoneNumberIdentifier),
                Helpers.FromByteStringToGuid(initiateRequest.AppDeviceIdentifier),
                initiateRequest.Purpose,
                initiateRequest.Type,
                writer, CultureName
            ));

        if (initiationResult.IsErr) throw GrpcFailureException.FromDomainFailure(initiationResult.UnwrapErr());

        await streamingTask;
    }

    public override async Task<CipherPayload> ValidatePhoneNumber(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptionResult = await DecryptRequest(request, context);
        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        ValidatePhoneNumberRequest validateRequest =
            Helpers.ParseFromBytes<ValidatePhoneNumberRequest>(decryptionResult.Unwrap());

        Result<PhoneNumberValidationResult, VerificationFlowFailure> validationResult =
            phoneNumberValidator.ValidatePhoneNumber(validateRequest.PhoneNumber, CultureName);

        if (validationResult.IsErr) throw GrpcFailureException.FromDomainFailure(validationResult.UnwrapErr());

        PhoneNumberValidationResult phoneValidationResult = validationResult.Unwrap();
        if (phoneValidationResult.IsValid)
        {
            EnsurePhoneNumberActorEvent ensurePhoneNumberActorEvent =
                new(phoneValidationResult.ParsedPhoneNumberE164!, phoneValidationResult.DetectedRegion,
                    Helpers.FromByteStringToGuid(validateRequest.AppDeviceIdentifier));

            Result<Guid, VerificationFlowFailure> ensurePhoneNumberResult = await VerificationFlowManagerActor
                .Ask<Result<Guid, VerificationFlowFailure>>(ensurePhoneNumberActorEvent);

            if (ensurePhoneNumberResult.IsOk)
            {
                ValidatePhoneNumberResponse validatePhoneNumberResponse = new()
                {
                    PhoneNumberIdentifier = Helpers.GuidToByteString(ensurePhoneNumberResult.Unwrap()),
                    Result = VerificationResult.Succeeded
                };

                return await EncryptAndReturnResponse(validatePhoneNumberResponse.ToByteArray(), context);
            }

            VerificationFlowFailure verificationFlowFailure = ensurePhoneNumberResult.UnwrapErr();
            ValidatePhoneNumberResponse response1 = new()
            {
                PhoneNumberIdentifier = ByteString.Empty,
                Result = VerificationResult.InvalidPhone,
                Message = verificationFlowFailure.Message
            };

            return await EncryptAndReturnResponse(response1.ToByteArray(), context);
        }

        ValidatePhoneNumberResponse response = new()
        {
            Result = VerificationResult.InvalidPhone,
            Message = phoneValidationResult.MessageKey
        };

        return await EncryptAndReturnResponse(response.ToByteArray(), context);
    }

    public override async Task<CipherPayload> VerifyOtp(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptionResult = await DecryptRequest(request, context);
        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        VerifyCodeRequest verifyRequest = Helpers.ParseFromBytes<VerifyCodeRequest>(decryptionResult.Unwrap());

        uint connectId = ServiceUtilities.ExtractConnectId(context);

        VerifyFlowActorEvent actorEvent = new(connectId, verifyRequest.Code, CultureName);

        Result<VerifyCodeResponse, VerificationFlowFailure> verificationResult = await VerificationFlowManagerActor
            .Ask<Result<VerifyCodeResponse, VerificationFlowFailure>>(actorEvent);

        if (verificationResult.IsErr) throw GrpcFailureException.FromDomainFailure(verificationResult.UnwrapErr());

        return await EncryptAndReturnResponse(verificationResult.Unwrap().ToByteArray(), context);
    }

    private async Task StreamCountdownUpdatesAsync(
        IServerStreamWriter<CipherPayload> responseStream,
        ChannelReader<Result<VerificationCountdownUpdate, VerificationFlowFailure>> reader,
        ServerCallContext context)
    {
        await foreach (Result<VerificationCountdownUpdate, VerificationFlowFailure> updateResult in
                       reader.ReadAllAsync(context.CancellationToken))
        {
            if (updateResult.IsErr) throw GrpcFailureException.FromDomainFailure(updateResult.UnwrapErr());

            Result<CipherPayload, EcliptixProtocolFailure> encryptResult = await EncryptRequest(
                updateResult.Unwrap().ToByteArray(),
                PubKeyExchangeType.DataCenterEphemeralConnect,
                context);

            if (encryptResult.IsErr) throw GrpcFailureException.FromDomainFailure(encryptResult.UnwrapErr());

            await responseStream.WriteAsync(encryptResult.Unwrap());
        }
    }

    private async Task<CipherPayload> EncryptAndReturnResponse(byte[] data, ServerCallContext context)
    {
        Result<CipherPayload, EcliptixProtocolFailure> encryptResult =
            await EncryptRequest(data, PubKeyExchangeType.DataCenterEphemeralConnect, context);

        if (encryptResult.IsErr) throw GrpcFailureException.FromDomainFailure(encryptResult.UnwrapErr());

        return encryptResult.Unwrap();
    }
}