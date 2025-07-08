using System.Threading.Channels;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
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
    IEcliptixActorRegistry actorRegistry,
    IPhoneNumberValidator phoneNumberValidator)
    : VerificationFlowServicesBase(actorRegistry)
{
    public override async Task InitiateVerification(CipherPayload request,
        IServerStreamWriter<CipherPayload> responseStream,
        ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptionResult = await DecryptPayloadAsync(request, context);
        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        InitiateVerificationRequest initiateRequest =
            Helpers.ParseFromBytes<InitiateVerificationRequest>(decryptionResult.Unwrap());
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Channel<Result<VerificationCountdownUpdate, VerificationFlowFailure>> channel =
            Channel.CreateUnbounded<Result<VerificationCountdownUpdate, VerificationFlowFailure>>();

        Task streamingTask = StreamCountdownUpdatesAsync(responseStream, channel.Reader, context);
        context.CancellationToken.Register(() => StopVerificationFlowActor(context, connectId));

        Result<Unit, VerificationFlowFailure> initiationResult = await VerificationFlowManagerActor
            .Ask<Result<Unit, VerificationFlowFailure>>(new InitiateVerificationFlowActorEvent(
                connectId,
                Helpers.FromByteStringToGuid(initiateRequest.PhoneNumberIdentifier),
                Helpers.FromByteStringToGuid(initiateRequest.AppDeviceIdentifier),
                initiateRequest.Purpose,
                initiateRequest.Type,
                channel.Writer,
                CultureName
            ), context.CancellationToken);

        if (initiationResult.IsErr) throw GrpcFailureException.FromDomainFailure(initiationResult.UnwrapErr());

        await streamingTask;
    }

    public override async Task<CipherPayload> ValidatePhoneNumber(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptionResult = await DecryptPayloadAsync(request, context);
        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        ValidatePhoneNumberRequest validateRequest =
            Helpers.ParseFromBytes<ValidatePhoneNumberRequest>(decryptionResult.Unwrap());

        Result<PhoneNumberValidationResult, VerificationFlowFailure> validationResult =
            phoneNumberValidator.ValidatePhoneNumber(validateRequest.PhoneNumber, CultureName);
        if (validationResult.IsErr) throw GrpcFailureException.FromDomainFailure(validationResult.UnwrapErr());

        PhoneNumberValidationResult phoneValidationResult = validationResult.Unwrap();

        if (phoneValidationResult.IsValid)
        {
            EnsurePhoneNumberActorEvent ensurePhoneNumberEvent = new(
                phoneValidationResult.ParsedPhoneNumberE164!,
                phoneValidationResult.DetectedRegion,
                Helpers.FromByteStringToGuid(validateRequest.AppDeviceIdentifier));

            Result<Guid, VerificationFlowFailure> ensurePhoneNumberResult = await VerificationFlowManagerActor
                .Ask<Result<Guid, VerificationFlowFailure>>(ensurePhoneNumberEvent, context.CancellationToken);

            ValidatePhoneNumberResponse response = ensurePhoneNumberResult.Match(
                guid => new ValidatePhoneNumberResponse
                {
                    PhoneNumberIdentifier = Helpers.GuidToByteString(guid),
                    Result = VerificationResult.Succeeded
                },
                failure => new ValidatePhoneNumberResponse
                {
                    PhoneNumberIdentifier = ByteString.Empty,
                    Result = VerificationResult.InvalidPhone,
                    Message = failure.Message
                });

            return await EncryptAndReturnResponse(response.ToByteArray(), context);
        }
        else
        {
            ValidatePhoneNumberResponse response = new()
            {
                Result = VerificationResult.InvalidPhone,
                Message = phoneValidationResult.MessageKey
            };
            return await EncryptAndReturnResponse(response.ToByteArray(), context);
        }
    }

    public override async Task<CipherPayload> VerifyOtp(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptionResult = await DecryptPayloadAsync(request, context);
        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        VerifyCodeRequest verifyRequest = Helpers.ParseFromBytes<VerifyCodeRequest>(decryptionResult.Unwrap());
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        VerifyFlowActorEvent actorEvent = new(connectId, verifyRequest.Code, CultureName);

        Result<VerifyCodeResponse, VerificationFlowFailure> verificationResult = await VerificationFlowManagerActor
            .Ask<Result<VerifyCodeResponse, VerificationFlowFailure>>(actorEvent, context.CancellationToken);

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

            CipherPayload encryptedPayload =
                await EncryptAndReturnResponse(updateResult.Unwrap().ToByteArray(), context);
            await responseStream.WriteAsync(encryptedPayload);
        }
    }

    private async Task<CipherPayload> EncryptAndReturnResponse(byte[] data, ServerCallContext context)
    {
        Result<CipherPayload, EcliptixProtocolFailure> encryptResult = await EncryptPayloadAsync(data, context);
        if (encryptResult.IsErr) throw GrpcFailureException.FromDomainFailure(encryptResult.UnwrapErr());
        return encryptResult.Unwrap();
    }

    private async Task<Result<CipherPayload, EcliptixProtocolFailure>> EncryptPayloadAsync(byte[] payload,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);
        EncryptPayloadActorEvent encryptCommand = new(PubKeyExchangeType.DataCenterEphemeralConnect, payload);
        ForwardToConnectActorEvent encryptForwarder = new(connectId, encryptCommand);

        return await ProtocolActor.Ask<Result<CipherPayload, EcliptixProtocolFailure>>(
            encryptForwarder, context.CancellationToken);
    }

    private async Task<Result<byte[], EcliptixProtocolFailure>> DecryptPayloadAsync(CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);
        DecryptCipherPayloadActorEvent decryptEvent = new(PubKeyExchangeType.DataCenterEphemeralConnect, request);
        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptEvent);

        return await ProtocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(
            decryptForwarder, context.CancellationToken);
    }
}