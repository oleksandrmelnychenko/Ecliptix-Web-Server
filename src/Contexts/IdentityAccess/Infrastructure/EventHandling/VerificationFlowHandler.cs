using System.Threading.Channels;
using Akka.Actor;
using System.Globalization;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Memberships.MobileNumberValidation;
using Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Membership;
using Google.Protobuf;
using Grpc.Core;
using Ecliptix.SharedKernel.Grpc;
using Ecliptix.SharedKernel.Grpc.Utilities.CipherPayloadHandler;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Serilog;
using Ecliptix.SharedKernel.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;

namespace Ecliptix.IdentityAccess.Infrastructure.EventHandling;

public sealed class VerificationFlowHandler(
    IEcliptixActorRegistry actorRegistry,
    IMobileNumberValidator phoneNumberValidator,
    IGrpcCipherService grpcCipherService,
    IOptions<SecurityConfiguration> securityConfig)
{
    private readonly GrpcSecurityService _service = new(grpcCipherService, securityConfig);
    private readonly IActorRef _verificationFlowManagerActor = actorRegistry.Get(ActorIds.VerificationFlowManagerActor);
    private readonly string _cultureName = CultureInfo.CurrentCulture.Name;

    public async Task InitiateVerification(
        SecureEnvelope request,
        IServerStreamWriter<SecureEnvelope> responseStream,
        ServerCallContext context)
    {
        Result<SecureEnvelope, FailureBase> result =
            await _service
                .ExecuteEncryptedStreamingOperationAsync<OtpVerificationRequest, OtpCountdownUpdate>(
                    request, context,
                    async (initiateRequest, connectId, idempotencyKey, cancellationToken) =>
                    {
                        BoundedChannelOptions channelOptions =
                            new(GrpcServiceConstants.ChannelOptions.BoundedChannelCapacity)
                            {
                                FullMode = BoundedChannelFullMode.Wait,
                                SingleReader = true,
                                SingleWriter = false
                            };

                        using CancellationTokenSource linkedCancellationTokenSource =
                            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, context.CancellationToken);

                        Channel<Result<OtpCountdownUpdate, VerificationFlowFailure>> channel =
                            Channel.CreateBounded<Result<OtpCountdownUpdate, VerificationFlowFailure>>(
                                channelOptions);
                        using IDisposable registration = context.CancellationToken.Register(() =>
                            StopVerificationFlowActor(context, connectId));

                        Log.Information("[verification.flow.grpc.start] ConnectId {ConnectId} Purpose {Purpose}",
                            connectId, initiateRequest.Purpose);

                        Task streamingTask = StreamCountdownUpdatesAsync(responseStream, channel.Reader, context, linkedCancellationTokenSource.Token);

                        Guid deviceId = DeviceIdResolver.ResolveDeviceIdFromContext(context);

                        Task<Result<Unit, VerificationFlowFailure>> initiationTask =
                            _verificationFlowManagerActor.Ask<Result<Unit, VerificationFlowFailure>>(
                                new InitiateVerificationFlowCommand(
                                    connectId,
                                    Helpers.FromByteStringToGuid(initiateRequest.MobileNumberId),
                                    deviceId,
                                    ConvertProtoPurposeToDomain(initiateRequest.Purpose),
                                    initiateRequest.Type,
                                    channel.Writer,
                                    _cultureName,
                                    idempotencyKey,
                                    linkedCancellationTokenSource.Token
                                ),
                                TimeoutConfiguration.Actor.StreamingTimeout);

                        Result<Unit, VerificationFlowFailure> initiationResult =
                            await initiationTask.WaitAsync(linkedCancellationTokenSource.Token).ConfigureAwait(false);

                        if (initiationResult.IsErr)
                        {
                            return Result<OtpCountdownUpdate, FailureBase>.Err(initiationResult.UnwrapErr());
                        }

                        try
                        {
                            await streamingTask.ConfigureAwait(false);
                            Log.Information("[verification.flow.grpc.completed] ConnectId {ConnectId}", connectId);
                        }
                        catch (OperationCanceledException ex)
                        {
                            Log.Information("[verification.flow.grpc.cancelled] ConnectId {ConnectId}", connectId);
                            Log.Debug(ex, "[verification.flow.grpc.cancelled] ConnectId {ConnectId}", connectId);
                        }

                        return Result<OtpCountdownUpdate, FailureBase>.Ok(new OtpCountdownUpdate());
                    });

        if (result.IsOk)
        {
            await responseStream.WriteAsync(result.Unwrap());
        }
    }

    public async Task<SecureEnvelope> ValidateMobileNumber(SecureEnvelope request, ServerCallContext context) =>
        await _service.ExecuteEncryptedOperationAsync<MobileNumberValidateRequest, MobileNumberValidateResponse>(
            request, context,
            async (message, _, _, cancellationToken) =>
            {
                Result<MobileNumberValidationResult, VerificationFlowFailure> validationResult =
                    phoneNumberValidator.ValidateMobileNumber(message.MobileNumber, _cultureName);

                if (validationResult.IsErr)
                {
                    return Result<MobileNumberValidateResponse, FailureBase>.Err(validationResult.UnwrapErr());
                }

                MobileNumberValidationResult phoneValidationResult = validationResult.Unwrap();

                if (phoneValidationResult.IsValid)
                {
                    Guid deviceId = DeviceIdResolver.ResolveDeviceIdFromContext(context);

                    ValidateMobileNumberCommand ensureMobileNumberEvent = new(
                        phoneValidationResult.ParsedMobileNumberE164.Value!,
                        phoneValidationResult.DetectedRegion.Match(region => region, () => string.Empty),
                        deviceId,
                        cancellationToken);

                    Task<Result<Guid, VerificationFlowFailure>> ensureMobileTask =
                        _verificationFlowManagerActor.Ask<Result<Guid, VerificationFlowFailure>>(
                            ensureMobileNumberEvent,
                            TimeoutConfiguration.Actor.AskTimeout);

                    Result<Guid, VerificationFlowFailure> ensureMobileNumberResult =
                        await ensureMobileTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                    MobileNumberValidateResponse response = ensureMobileNumberResult.Match(
                        guid => new MobileNumberValidateResponse
                        {
                            MobileNumberId = Helpers.GuidToByteString(guid),
                            Result = OtpVerificationResult.Succeeded
                        },
                        failure => new MobileNumberValidateResponse
                        {
                            MobileNumberId = ByteString.Empty,
                            Result = OtpVerificationResult.InvalidMobile,
                            Message = failure.Message
                        });
                    return Result<MobileNumberValidateResponse, FailureBase>.Ok(response);
                }
                else
                {
                    MobileNumberValidateResponse response = new()
                    {
                        Result = OtpVerificationResult.InvalidMobile,
                        Message = phoneValidationResult.LocalizedMessage.Value!
                    };
                    return Result<MobileNumberValidateResponse, FailureBase>.Ok(response);
                }
            });

    public async Task<SecureEnvelope> RecoverySecretKeyMobileVerification(SecureEnvelope request,
        ServerCallContext context) =>
        await _service.ExecuteEncryptedOperationAsync<MobileNumberValidateRequest, MobileNumberValidateResponse>(
            request, context,
            async (message, _, _, cancellationToken) =>
            {
                Result<MobileNumberValidationResult, VerificationFlowFailure> validationResult =
                    phoneNumberValidator.ValidateMobileNumber(message.MobileNumber, _cultureName);
                if (validationResult.IsErr)
                {
                    return Result<MobileNumberValidateResponse, FailureBase>.Err(validationResult.UnwrapErr());
                }

                MobileNumberValidationResult phoneValidationResult = validationResult.Unwrap();

                if (phoneValidationResult.IsValid)
                {
                    VerifyMobileForSecretKeyRecoveryCommand verifyMobileEvent = new(
                        phoneValidationResult.ParsedMobileNumberE164.Value!,
                        phoneValidationResult.DetectedRegion.Match(region => region, () => string.Empty),
                        cancellationToken);

                    Task<Result<Guid, VerificationFlowFailure>> verifyMobileTask =
                        _verificationFlowManagerActor.Ask<Result<Guid, VerificationFlowFailure>>(
                            verifyMobileEvent,
                            TimeoutConfiguration.Actor.AskTimeout);
                    Result<Guid, VerificationFlowFailure> verifyMobileResult =
                        await verifyMobileTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                    MobileNumberValidateResponse response = verifyMobileResult.Match(
                        guid => new MobileNumberValidateResponse
                        {
                            MobileNumberId = Helpers.GuidToByteString(guid),
                            Result = OtpVerificationResult.Succeeded
                        },
                        failure => new MobileNumberValidateResponse
                        {
                            MobileNumberId = ByteString.Empty,
                            Result = OtpVerificationResult.InvalidMobile,
                            Message = failure.Message
                        }
                    );

                    return Result<MobileNumberValidateResponse, FailureBase>.Ok(response);
                }
                else
                {
                    MobileNumberValidateResponse response = new()
                    {
                        Result = OtpVerificationResult.InvalidMobile,
                        Message = phoneValidationResult.LocalizedMessage.Value!
                    };
                    return Result<MobileNumberValidateResponse, FailureBase>.Ok(response);
                }
            });

    public async Task<SecureEnvelope> CheckMobileNumberAvailability(SecureEnvelope request, ServerCallContext context) =>
        await _service.ExecuteEncryptedOperationAsync<MobileNumberAvailabilityRequest, MobileNumberAvailabilityResponse>(
            request, context,
            async (message, _, _, cancellationToken) =>
            {
                Guid deviceId = DeviceIdResolver.ResolveDeviceIdFromContext(context);

                ExistsMobileNumberQuery actorEvent = new(
                    Helpers.FromByteStringToGuid(message.MobileNumberId),
                    deviceId,
                    cancellationToken);

                Task<Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>> checkTask =
                    _verificationFlowManagerActor.Ask<Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>>(
                        actorEvent,
                        TimeoutConfiguration.Actor.AskTimeout);

                Result<MobileNumberAvailabilityResponse, VerificationFlowFailure> checkResult =
                    await checkTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                return checkResult.Match(
                    response => Result<MobileNumberAvailabilityResponse, FailureBase>.Ok(new MobileNumberAvailabilityResponse
                    {
                        Status = response.Status,
                        CanRegister = response.CanRegister,
                        CanContinue = response.CanContinue,
                        ExistingMembershipId = response.ExistingMembershipId,
                        RegisteredDeviceId = response.RegisteredDeviceId,
                        CreationStatus = response.CreationStatus,
                        ActivityStatus = response.ActivityStatus,
                        LocalizationKey = response.LocalizationKey
                    }),
                    Result<MobileNumberAvailabilityResponse, FailureBase>.Err
                );
            });

    public async Task<SecureEnvelope> VerifyOtp(SecureEnvelope request, ServerCallContext context) =>
        await _service.ExecuteEncryptedOperationAsync<OtpCodeVerifyRequest, OtpCodeVerifyResponse>(request, context,
            async (message, _, _, cancellationToken) =>
            {
                VerifyFlowCommand actorEvent = new(message.StreamConnectId, message.Code, _cultureName, cancellationToken);
                actorEvent = actorEvent with { CancellationToken = cancellationToken };

                Task<Result<OtpCodeVerifyResponse, VerificationFlowFailure>> verifyTask =
                    _verificationFlowManagerActor.Ask<Result<OtpCodeVerifyResponse, VerificationFlowFailure>>(
                        actorEvent,
                        TimeoutConfiguration.Actor.AskTimeout);

                Result<OtpCodeVerifyResponse, VerificationFlowFailure> verificationResult =
                    await verifyTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                return verificationResult.Match(
                    Result<OtpCodeVerifyResponse, FailureBase>.Ok,
                    Result<OtpCodeVerifyResponse, FailureBase>.Err
                );
            });

    private async Task StreamCountdownUpdatesAsync(
        IServerStreamWriter<SecureEnvelope> responseStream,
        ChannelReader<Result<OtpCountdownUpdate, VerificationFlowFailure>> reader,
        ServerCallContext context,
        CancellationToken cancellationToken)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        try
        {
            await foreach (Result<OtpCountdownUpdate, VerificationFlowFailure> updateResult in reader.ReadAllAsync(
                               cancellationToken))
            {
                SecureEnvelope payload;

                if (updateResult.IsErr)
                {
                    VerificationFlowFailure failure = updateResult.UnwrapErr();
                    Log.Warning("[verification.flow.grpc.update-error] ConnectId {ConnectId} ErrorType {ErrorType}",
                        connectId, failure.GetType().Name);

                    payload = await grpcCipherService.CreateFailureResponse(updateResult.UnwrapErr(), connectId, context);
                }
                else
                {
                    OtpCountdownUpdate update = updateResult.Unwrap();

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
                    }
                }

                await responseStream.WriteAsync(payload, cancellationToken);
            }
        }
        catch (OperationCanceledException ex)
        {
            Log.Information("[verification.flow.grpc.stream-cancelled] ConnectId {ConnectId}", connectId);
            Log.Debug(ex, "[verification.flow.grpc.stream-cancelled] ConnectId {ConnectId}", connectId);
        }
    }

    private static Ecliptix.IdentityAccess.Domain.Memberships.OtpVerificationPurpose ConvertProtoPurposeToDomain(
        OtpVerificationPurpose protoPurpose)
    {
        return protoPurpose switch
        {
            OtpVerificationPurpose.Registration => Domain.Memberships.OtpVerificationPurpose.Registration,
            OtpVerificationPurpose.Login => Domain.Memberships.OtpVerificationPurpose.Login,
            OtpVerificationPurpose.PasswordRecovery => Domain.Memberships.OtpVerificationPurpose.SecureKeyRecovery,
            _ => Domain.Memberships.OtpVerificationPurpose.Unspecified
        };
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
