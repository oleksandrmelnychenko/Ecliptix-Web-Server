using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Core.Services.Utilities.CipherPayloadHandler;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.Membership;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Memberships;

public class VerificationFlowServices(
    IEcliptixActorRegistry actorRegistry,
    IPhoneNumberValidator phoneNumberValidator,
    IGrpcCipherService grpcCipherService)
    : VerificationFlowServicesBase(actorRegistry, grpcCipherService)
{
    public override async Task InitiateVerification(
        CipherPayload request,
        IServerStreamWriter<CipherPayload> responseStream,
        ServerCallContext context)
    {
        Result<Unit, FailureBase> result =
            await ExecuteWithDecryptionForStreaming<InitiateVerificationRequest, VerificationFlowFailure>(
                request, context,
                async (initiateRequest, connectId, ct) =>
                {
                    Channel<Result<VerificationCountdownUpdate, VerificationFlowFailure>> channel =
                        Channel.CreateUnbounded<Result<VerificationCountdownUpdate, VerificationFlowFailure>>();
                    Task streamingTask = StreamCountdownUpdatesAsync(responseStream, channel.Reader, context);

                    context.CancellationToken.Register(() => StopVerificationFlowActor(context, connectId));

                    Result<Unit, VerificationFlowFailure> initiationResult = await VerificationFlowManagerActor
                        .Ask<Result<Unit, VerificationFlowFailure>>(
                            new InitiateVerificationFlowActorEvent(
                                connectId,
                                Helpers.FromByteStringToGuid(initiateRequest.PhoneNumberIdentifier),
                                Helpers.FromByteStringToGuid(initiateRequest.AppDeviceIdentifier),
                                initiateRequest.Purpose,
                                initiateRequest.Type,
                                channel.Writer,
                                CultureName
                            ), ct);

                    if (initiationResult.IsErr)
                        return Result<Unit, VerificationFlowFailure>.Err(initiationResult.UnwrapErr());

                    await streamingTask;
                    return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
                });

        if (result.IsErr)
        {
            CipherPayload payload = await GrpcCipherService.CreateFailureResponse(result.UnwrapErr(),
                ServiceUtilities.ExtractConnectId(context), context);
            await responseStream.WriteAsync(payload);
        }
    }


    public override async Task<CipherPayload> ValidatePhoneNumber(CipherPayload request, ServerCallContext context) =>
        await ExecuteWithDecryption<ValidatePhoneNumberRequest, ValidatePhoneNumberResponse>(request, context,
            async (message, connectId, ct) =>
            {
                Result<PhoneNumberValidationResult, VerificationFlowFailure> validationResult =
                    phoneNumberValidator.ValidatePhoneNumber(message.PhoneNumber, CultureName);

                if (validationResult.IsErr)
                {
                    return await GrpcCipherService.CreateFailureResponse(validationResult.UnwrapErr(), connectId,
                        context);
                }

                PhoneNumberValidationResult phoneValidationResult = validationResult.Unwrap();

                if (phoneValidationResult.IsValid)
                {
                    EnsurePhoneNumberActorEvent ensurePhoneNumberEvent = new(
                        phoneValidationResult.ParsedPhoneNumberE164!,
                        phoneValidationResult.DetectedRegion,
                        Helpers.FromByteStringToGuid(message.AppDeviceIdentifier));

                    Result<Guid, VerificationFlowFailure> ensurePhoneNumberResult = await VerificationFlowManagerActor
                        .Ask<Result<Guid, VerificationFlowFailure>>(ensurePhoneNumberEvent, ct);

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

                    return await GrpcCipherService.CreateSuccessResponse<ValidatePhoneNumberResponse>(
                        response.ToByteArray(), connectId, context);
                }
                else
                {
                    ValidatePhoneNumberResponse response = new()
                    {
                        Result = VerificationResult.InvalidPhone,
                        Message = phoneValidationResult.MessageKey
                    };
                    return await GrpcCipherService.CreateSuccessResponse<ValidatePhoneNumberResponse>(
                        response.ToByteArray(), connectId, context);
                }
            });


    public override async Task<CipherPayload> RecoverySecretKeyPhoneVerification(CipherPayload request,
        ServerCallContext context) =>
        await ExecuteWithDecryption<ValidatePhoneNumberRequest, ValidatePhoneNumberResponse>(request, context,
            async (message, connectId, ct) =>
            {
                Result<PhoneNumberValidationResult, VerificationFlowFailure> validationResult =
                    phoneNumberValidator.ValidatePhoneNumber(message.PhoneNumber, CultureName);
                if (validationResult.IsErr)
                {
                    return await GrpcCipherService.CreateFailureResponse(validationResult.UnwrapErr(), connectId,
                        context);
                }

                PhoneNumberValidationResult phoneValidationResult = validationResult.Unwrap();

                if (phoneValidationResult.IsValid)
                {
                    VerifyPhoneForSecretKeyRecoveryActorEvent verifyPhoneEvent = new(
                        phoneValidationResult.ParsedPhoneNumberE164!,
                        phoneValidationResult.DetectedRegion);

                    Result<Guid, VerificationFlowFailure> verifyPhoneResult = await VerificationFlowManagerActor
                        .Ask<Result<Guid, VerificationFlowFailure>>(verifyPhoneEvent, ct);

                    ValidatePhoneNumberResponse response = verifyPhoneResult.Match(
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
                        }
                    );

                    return await GrpcCipherService.CreateSuccessResponse<ValidatePhoneNumberResponse>(
                        response.ToByteArray(), connectId, context);
                }
                else
                {
                    ValidatePhoneNumberResponse response = new()
                    {
                        Result = VerificationResult.InvalidPhone,
                        Message = phoneValidationResult.MessageKey
                    };
                    return await GrpcCipherService.CreateSuccessResponse<ValidatePhoneNumberResponse>(
                        response.ToByteArray(), connectId, context);
                }
            });

    public override async Task<CipherPayload> VerifyOtp(CipherPayload request, ServerCallContext context) =>
        await ExecuteWithDecryption<VerifyCodeRequest, VerifyCodeRequest>(request, context,
            async (message, connectId, ct) =>
            {
                VerifyFlowActorEvent actorEvent = new(connectId, message.Code, CultureName);

                Result<VerifyCodeResponse, VerificationFlowFailure> verificationResult =
                    await VerificationFlowManagerActor
                        .Ask<Result<VerifyCodeResponse, VerificationFlowFailure>>(actorEvent, ct);

                return await GrpcCipherService.ProcessResult(verificationResult, connectId, context);
            });

    private async Task StreamCountdownUpdatesAsync(
        IServerStreamWriter<CipherPayload> responseStream,
        ChannelReader<Result<VerificationCountdownUpdate, VerificationFlowFailure>> reader,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);
        await foreach (Result<VerificationCountdownUpdate, VerificationFlowFailure> updateResult in reader.ReadAllAsync(context.CancellationToken))
        {
            CipherPayload payload;

            if (updateResult.IsErr)
            {
                payload = await GrpcCipherService.CreateFailureResponse(updateResult.UnwrapErr(), connectId, context);
            }
            else
            {
                Result<CipherPayload, FailureBase> encryptResult =
                    await GrpcCipherService.EncryptPayload(updateResult.Unwrap().ToByteArray(), connectId, context);
                if (encryptResult.IsErr)
                {
                    payload = await GrpcCipherService.CreateFailureResponse(encryptResult.UnwrapErr(), connectId,
                        context);
                }
                else
                {
                    payload = encryptResult.Unwrap();
                }
            }

            await responseStream.WriteAsync(payload);
        }
    }
}