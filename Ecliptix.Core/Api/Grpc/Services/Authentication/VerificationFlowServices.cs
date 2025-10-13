using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.Core.Api.Grpc.Base;
using System.Globalization;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.MobileNumberValidation;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Common;
using Google.Protobuf;
using Grpc.Core;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Protobuf.Account;

namespace Ecliptix.Core.Api.Grpc.Services.Authentication;

internal sealed class VerificationFlowServices(
    IEcliptixActorRegistry actorRegistry,
    IMobileNumberValidator phoneNumberValidator,
    IGrpcCipherService grpcCipherService)
    : AuthVerificationServices.AuthVerificationServicesBase
{
    private readonly RpcServiceBase _baseService = new(grpcCipherService);
    private readonly IActorRef _verificationFlowManagerActor = actorRegistry.Get(ActorIds.VerificationFlowManagerActor);
    private readonly string _cultureName = CultureInfo.CurrentCulture.Name;

    public override async Task InitiateVerification(
        SecureEnvelope request,
        IServerStreamWriter<SecureEnvelope> responseStream,
        ServerCallContext context)
    {
        Result<Unit, FailureBase> result =
            await _baseService
                .ExecuteEncryptedStreamingOperationAsync<InitiateVerificationRequest, VerificationFlowFailure>(
                    request, context,
                    async (initiateRequest, connectId, ct) =>
                    {
                        BoundedChannelOptions channelOptions =
                            new(GrpcServiceConstants.ChannelOptions.BoundedChannelCapacity)
                            {
                                FullMode = BoundedChannelFullMode.Wait,
                                SingleReader = true,
                                SingleWriter = false
                            };

                        Channel<Result<VerificationCountdownUpdate, VerificationFlowFailure>> channel =
                            Channel.CreateBounded<Result<VerificationCountdownUpdate, VerificationFlowFailure>>(
                                channelOptions);
                        Task streamingTask = StreamCountdownUpdatesAsync(responseStream, channel.Reader, context);

                        context.CancellationToken.Register(() => StopVerificationFlowActor(context, connectId));

                        Result<Unit, VerificationFlowFailure> initiationResult = await _verificationFlowManagerActor
                            .Ask<Result<Unit, VerificationFlowFailure>>(
                                new InitiateVerificationFlowActorEvent(
                                    connectId,
                                    Helpers.FromByteStringToGuid(initiateRequest.MobileNumberIdentifier),
                                    Helpers.FromByteStringToGuid(initiateRequest.AppDeviceIdentifier),
                                    initiateRequest.Purpose,
                                    initiateRequest.Type,
                                    channel.Writer,
                                    _cultureName
                                ), ct);

                        if (initiationResult.IsErr)
                            return Result<Unit, VerificationFlowFailure>.Err(initiationResult.UnwrapErr());

                        await streamingTask;
                        return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
                    });

        if (result.IsErr)
        {
            SecureEnvelope payload = await grpcCipherService.CreateFailureResponse(result.UnwrapErr(),
                ServiceUtilities.ExtractConnectId(context), context);
            await responseStream.WriteAsync(payload);
        }
    }

    public override async Task<SecureEnvelope> ValidateMobileNumber(SecureEnvelope request, ServerCallContext context) =>
        await _baseService.ExecuteEncryptedOperationAsync<ValidateMobileNumberRequest, ValidateMobileNumberResponse>(
            request, context,
            async (message, _, ct) =>
            {
                Result<MobileNumberValidationResult, VerificationFlowFailure> validationResult =
                    phoneNumberValidator.ValidateMobileNumber(message.MobileNumber, _cultureName);

                if (validationResult.IsErr)
                {
                    return Result<ValidateMobileNumberResponse, FailureBase>.Err(validationResult.UnwrapErr());
                }

                MobileNumberValidationResult phoneValidationResult = validationResult.Unwrap();

                if (phoneValidationResult.IsValid)
                {
                    EnsureMobileNumberActorEvent ensureMobileNumberEvent = new(
                        phoneValidationResult.ParsedMobileNumberE164!,
                        phoneValidationResult.DetectedRegion,
                        Helpers.FromByteStringToGuid(message.AppDeviceIdentifier));

                    Result<Guid, VerificationFlowFailure> ensureMobileNumberResult = await _verificationFlowManagerActor
                        .Ask<Result<Guid, VerificationFlowFailure>>(ensureMobileNumberEvent, ct);

                    ValidateMobileNumberResponse response = ensureMobileNumberResult.Match(
                        guid => new ValidateMobileNumberResponse
                        {
                            MobileNumberIdentifier = Helpers.GuidToByteString(guid),
                            Result = VerificationResult.Succeeded
                        },
                        failure => new ValidateMobileNumberResponse
                        {
                            MobileNumberIdentifier = ByteString.Empty,
                            Result = VerificationResult.InvalidMobile,
                            Message = failure.Message
                        });
                    return Result<ValidateMobileNumberResponse, FailureBase>.Ok(response);
                }
                else
                {
                    ValidateMobileNumberResponse response = new()
                    {
                        Result = VerificationResult.InvalidMobile,
                        Message = phoneValidationResult.MessageKey
                    };
                    return Result<ValidateMobileNumberResponse, FailureBase>.Ok(response);
                }
            });

    public override async Task<SecureEnvelope> RecoverySecretKeyMobileVerification(SecureEnvelope request,
        ServerCallContext context) =>
        await _baseService.ExecuteEncryptedOperationAsync<ValidateMobileNumberRequest, ValidateMobileNumberResponse>(
            request, context,
            async (message, _, ct) =>
            {
                Result<MobileNumberValidationResult, VerificationFlowFailure> validationResult =
                    phoneNumberValidator.ValidateMobileNumber(message.MobileNumber, _cultureName);
                if (validationResult.IsErr)
                {
                    return Result<ValidateMobileNumberResponse, FailureBase>.Err(validationResult.UnwrapErr());
                }

                MobileNumberValidationResult phoneValidationResult = validationResult.Unwrap();

                if (phoneValidationResult.IsValid)
                {
                    VerifyMobileForSecretKeyRecoveryActorEvent verifyMobileEvent = new(
                        phoneValidationResult.ParsedMobileNumberE164!,
                        phoneValidationResult.DetectedRegion);

                    Result<Guid, VerificationFlowFailure> verifyMobileResult = await _verificationFlowManagerActor
                        .Ask<Result<Guid, VerificationFlowFailure>>(verifyMobileEvent, ct);

                    ValidateMobileNumberResponse response = verifyMobileResult.Match(
                        guid => new ValidateMobileNumberResponse
                        {
                            MobileNumberIdentifier = Helpers.GuidToByteString(guid),
                            Result = VerificationResult.Succeeded
                        },
                        failure => new ValidateMobileNumberResponse
                        {
                            MobileNumberIdentifier = ByteString.Empty,
                            Result = VerificationResult.InvalidMobile,
                            Message = failure.Message
                        }
                    );

                    return Result<ValidateMobileNumberResponse, FailureBase>.Ok(response);
                }
                else
                {
                    ValidateMobileNumberResponse response = new()
                    {
                        Result = VerificationResult.InvalidMobile,
                        Message = phoneValidationResult.MessageKey
                    };
                    return Result<ValidateMobileNumberResponse, FailureBase>.Ok(response);
                }
            });

    public override async Task<SecureEnvelope> VerifyOtp(SecureEnvelope request, ServerCallContext context) =>
        await _baseService.ExecuteEncryptedOperationAsync<VerifyCodeRequest, VerifyCodeResponse>(request, context,
            async (message, _, ct) =>
            {
                VerifyFlowActorEvent actorEvent = new(message.StreamConnectId, message.Code, _cultureName);

                Result<VerifyCodeResponse, VerificationFlowFailure> verificationResult =
                    await _verificationFlowManagerActor
                        .Ask<Result<VerifyCodeResponse, VerificationFlowFailure>>(actorEvent, ct);

                return verificationResult.Match(
                    Result<VerifyCodeResponse, FailureBase>.Ok,
                    Result<VerifyCodeResponse, FailureBase>.Err
                );
            });

    private async Task StreamCountdownUpdatesAsync(
        IServerStreamWriter<SecureEnvelope> responseStream,
        ChannelReader<Result<VerificationCountdownUpdate, VerificationFlowFailure>> reader,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        try
        {
            await foreach (Result<VerificationCountdownUpdate, VerificationFlowFailure> updateResult in reader.ReadAllAsync(
                               context.CancellationToken))
            {
                SecureEnvelope payload;

                if (updateResult.IsErr)
                {
                    payload = await grpcCipherService.CreateFailureResponse(updateResult.UnwrapErr(), connectId, context);
                }
                else
                {
                    VerificationCountdownUpdate update = updateResult.Unwrap();

                    Result<SecureEnvelope, FailureBase> encryptResult =
                        await grpcCipherService.EncryptEnvelop(update.ToByteArray(), connectId, context);

                    if (encryptResult.IsErr)
                    {
                        payload = await grpcCipherService.CreateFailureResponse(encryptResult.UnwrapErr(), connectId,
                            context);
                    }
                    else
                    {
                        payload = encryptResult.Unwrap();

                        if (update.Status == VerificationCountdownUpdate.Types.CountdownUpdateStatus.SessionExpired)
                        {
                            ActorSystem actorSystem =
                                context.GetHttpContext().RequestServices.GetRequiredService<ActorSystem>();
                            actorSystem.EventStream.Publish(new SessionExpiredMessageDeliveredEvent(connectId));
                        }
                    }
                }

                await responseStream.WriteAsync(payload);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static void StopVerificationFlowActor(ServerCallContext context, uint connectId)
    {
        ActorSystem actorSystem = context.GetHttpContext().RequestServices.GetRequiredService<ActorSystem>();

        string actorName = string.Format(GrpcServiceConstants.ActorPaths.FlowActorNameFormat, connectId);
        string actorPath = string.Format(GrpcServiceConstants.ActorPaths.VerificationFlowActorPathFormat,
            nameof(VerificationFlowManagerActor), actorName);

        ActorSelection? actorSelection = actorSystem.ActorSelection(actorPath);
        actorSelection.Tell(new PrepareForTerminationMessage());
    }
}