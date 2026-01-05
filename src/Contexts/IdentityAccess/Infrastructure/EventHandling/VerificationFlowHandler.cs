using System.Diagnostics;
using System.Threading.Channels;
using Akka.Actor;
using System.Globalization;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.MobileNumber;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Memberships.MobileNumberValidation;
using Ecliptix.IdentityAccess.Domain.Memberships.Instrumentation;
using Ecliptix.IdentityAccess.Domain.Memberships.WorkerActors.VerificationFlow;
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

/// <summary>
/// Internal command handler for verification flows (used via gateway).
/// </summary>
public sealed class VerificationFlowHandler
{
    private readonly GrpcSecurityService _service;
    private readonly IActorRef _verificationFlowManagerActor;
    private readonly IMobileNumberValidator _phoneNumberValidator;
    private readonly IGrpcCipherService _grpcCipherService;
    private readonly string _cultureName = CultureInfo.CurrentCulture.Name;

    public VerificationFlowHandler(
        IEcliptixActorRegistry actorRegistry,
        IMobileNumberValidator phoneNumberValidator,
        IGrpcCipherService grpcCipherService,
        IOptions<SecurityConfiguration> securityConfig)
    {
        _service = new GrpcSecurityService(grpcCipherService, securityConfig);
        _verificationFlowManagerActor = actorRegistry.Get(ActorIds.VerificationFlowManagerActor);
        _phoneNumberValidator = phoneNumberValidator;
        _grpcCipherService = grpcCipherService;
    }

    public async Task InitiateVerification(
        SecureEnvelope request,
        IServerStreamWriter<SecureEnvelope> responseStream,
        ServerCallContext context)
    {
        Result<SecureEnvelope, FailureBase> result =
            await _service
                .ExecuteEncryptedStreamingOperationAsync<InitiateVerificationRequest, VerificationCountdownUpdate>(
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

                        using CancellationTokenSource linkedCts =
                            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, context.CancellationToken);

                        Channel<Result<VerificationCountdownUpdate, VerificationFlowFailure>> channel =
                            Channel.CreateBounded<Result<VerificationCountdownUpdate, VerificationFlowFailure>>(
                                channelOptions);
                        using IDisposable registration = context.CancellationToken.Register(() =>
                            StopVerificationFlowActor(context, connectId));

                        Activity? flowActivity = VerificationFlowTelemetry.ActivitySource.StartActivity(
                            "verification.flow.stream",
                            ActivityKind.Server);
                        flowActivity?.SetTag("verification.connect_id", connectId);
                        flowActivity?.SetTag("verification.purpose", initiateRequest.Purpose.ToString());
                        Log.Information("[verification.flow.grpc.start] ConnectId {ConnectId} Purpose {Purpose}",
                            connectId, initiateRequest.Purpose);

                        Task streamingTask = StreamCountdownUpdatesAsync(responseStream, channel.Reader, context, linkedCts.Token);

                        Guid deviceId = DeviceIdResolver.ResolveDeviceIdFromContext(context);

                        Task<Result<Unit, VerificationFlowFailure>> initiationTask =
                            _verificationFlowManagerActor.Ask<Result<Unit, VerificationFlowFailure>>(
                                new InitiateVerificationFlowActorEvent(
                                    connectId,
                                    Helpers.FromByteStringToGuid(initiateRequest.MobileNumberIdentifier),
                                    deviceId,
                                    ConvertProtoPurposeToDomain(initiateRequest.Purpose),
                                    initiateRequest.Type,
                                    channel.Writer,
                                    _cultureName,
                                    idempotencyKey,
                                    flowActivity?.Context ?? Activity.Current?.Context ?? default,
                                    linkedCts.Token
                                ),
                                TimeoutConfiguration.Actor.StreamingTimeout);

                        Result<Unit, VerificationFlowFailure> initiationResult =
                            await initiationTask.WaitAsync(linkedCts.Token).ConfigureAwait(false);

                        if (initiationResult.IsErr)
                        {
                            flowActivity?.Dispose();
                            return Result<VerificationCountdownUpdate, FailureBase>.Err(initiationResult.UnwrapErr());
                        }

                        try
                        {
                            await streamingTask.ConfigureAwait(false);
                            Log.Information("[verification.flow.grpc.completed] ConnectId {ConnectId}", connectId);
                            flowActivity?.SetTag("verification.stream.completed", true);
                        }
                        catch (OperationCanceledException ex)
                        {
                            Log.Information("[verification.flow.grpc.cancelled] ConnectId {ConnectId}", connectId);
                            Log.Debug(ex, "[verification.flow.grpc.cancelled] ConnectId {ConnectId}", connectId);
                            flowActivity?.SetTag("verification.stream.completed", false);
                        }
                        finally
                        {
                            flowActivity?.Dispose();
                        }

                        return Result<VerificationCountdownUpdate, FailureBase>.Ok(new VerificationCountdownUpdate());
                    });

        if (result.IsOk)
        {
            await responseStream.WriteAsync(result.Unwrap());
        }
    }

    public async Task<SecureEnvelope> ValidateMobileNumber(SecureEnvelope request, ServerCallContext context) =>
        await _service.ExecuteEncryptedOperationAsync<ValidateMobileNumberRequest, ValidateMobileNumberResponse>(
            request, context,
            async (message, _, _, cancellationToken) =>
            {
                Result<MobileNumberValidationResult, VerificationFlowFailure> validationResult =
                    _phoneNumberValidator.ValidateMobileNumber(message.MobileNumber, _cultureName);

                if (validationResult.IsErr)
                {
                    return Result<ValidateMobileNumberResponse, FailureBase>.Err(validationResult.UnwrapErr());
                }

                MobileNumberValidationResult phoneValidationResult = validationResult.Unwrap();

                if (phoneValidationResult.IsValid)
                {
                    Guid deviceId = DeviceIdResolver.ResolveDeviceIdFromContext(context);

                    EnsureMobileNumberActorEvent ensureMobileNumberEvent = new(
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
                        Message = phoneValidationResult.LocalizedMessage.Value!
                    };
                    return Result<ValidateMobileNumberResponse, FailureBase>.Ok(response);
                }
            });

    public async Task<SecureEnvelope> RecoverySecretKeyMobileVerification(SecureEnvelope request,
        ServerCallContext context) =>
        await _service.ExecuteEncryptedOperationAsync<ValidateMobileNumberRequest, ValidateMobileNumberResponse>(
            request, context,
            async (message, _, _, cancellationToken) =>
            {
                Result<MobileNumberValidationResult, VerificationFlowFailure> validationResult =
                    _phoneNumberValidator.ValidateMobileNumber(message.MobileNumber, _cultureName);
                if (validationResult.IsErr)
                {
                    return Result<ValidateMobileNumberResponse, FailureBase>.Err(validationResult.UnwrapErr());
                }

                MobileNumberValidationResult phoneValidationResult = validationResult.Unwrap();

                if (phoneValidationResult.IsValid)
                {
                    VerifyMobileForSecretKeyRecoveryActorEvent verifyMobileEvent = new(
                        phoneValidationResult.ParsedMobileNumberE164.Value!,
                        phoneValidationResult.DetectedRegion.Match(region => region, () => string.Empty),
                        cancellationToken);

                    Task<Result<Guid, VerificationFlowFailure>> verifyMobileTask =
                        _verificationFlowManagerActor.Ask<Result<Guid, VerificationFlowFailure>>(
                            verifyMobileEvent,
                            TimeoutConfiguration.Actor.AskTimeout);
                    Result<Guid, VerificationFlowFailure> verifyMobileResult =
                        await verifyMobileTask.WaitAsync(cancellationToken).ConfigureAwait(false);

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
                        Message = phoneValidationResult.LocalizedMessage.Value!
                    };
                    return Result<ValidateMobileNumberResponse, FailureBase>.Ok(response);
                }
            });

    public async Task<SecureEnvelope> CheckMobileNumberAvailability(SecureEnvelope request, ServerCallContext context) =>
        await _service.ExecuteEncryptedOperationAsync<CheckMobileNumberAvailabilityRequest, CheckMobileNumberAvailabilityResponse>(
            request, context,
            async (message, _, _, cancellationToken) =>
            {
                Guid deviceId = DeviceIdResolver.ResolveDeviceIdFromContext(context);

                CheckMobileNumberAvailabilityActorEvent actorEvent = new(
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
                    response => Result<CheckMobileNumberAvailabilityResponse, FailureBase>.Ok(new CheckMobileNumberAvailabilityResponse
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
                    Result<CheckMobileNumberAvailabilityResponse, FailureBase>.Err
                );
            });

    public async Task<SecureEnvelope> VerifyOtp(SecureEnvelope request, ServerCallContext context) =>
        await _service.ExecuteEncryptedOperationAsync<VerifyCodeRequest, VerifyCodeResponse>(request, context,
            async (message, _, _, cancellationToken) =>
            {
                VerifyFlowActorEvent actorEvent = new(message.StreamConnectId, message.Code, _cultureName, cancellationToken);
                actorEvent = actorEvent with { CancellationToken = cancellationToken };

                Task<Result<VerifyCodeResponse, VerificationFlowFailure>> verifyTask =
                    _verificationFlowManagerActor.Ask<Result<VerifyCodeResponse, VerificationFlowFailure>>(
                        actorEvent,
                        TimeoutConfiguration.Actor.AskTimeout);

                Result<VerifyCodeResponse, VerificationFlowFailure> verificationResult =
                    await verifyTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                return verificationResult.Match(
                    Result<VerifyCodeResponse, FailureBase>.Ok,
                    Result<VerifyCodeResponse, FailureBase>.Err
                );
            });

    private async Task StreamCountdownUpdatesAsync(
        IServerStreamWriter<SecureEnvelope> responseStream,
        ChannelReader<Result<VerificationCountdownUpdate, VerificationFlowFailure>> reader,
        ServerCallContext context,
        CancellationToken cancellationToken)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        try
        {
            await foreach (Result<VerificationCountdownUpdate, VerificationFlowFailure> updateResult in reader.ReadAllAsync(
                               cancellationToken))
            {
                SecureEnvelope payload;

                if (updateResult.IsErr)
                {
                    VerificationFlowFailure failure = updateResult.UnwrapErr();
                    Log.Warning("[verification.flow.grpc.update-error] ConnectId {ConnectId} ErrorType {ErrorType}",
                        connectId, failure.GetType().Name);

                    payload = await _grpcCipherService.CreateFailureResponse(updateResult.UnwrapErr(), connectId, context);
                }
                else
                {
                    VerificationCountdownUpdate update = updateResult.Unwrap();

                    Result<SecureEnvelope, FailureBase> encryptResult =
                        await _grpcCipherService.EncryptEnvelop(update.ToByteArray(), connectId, context);

                    if (encryptResult.IsErr)
                    {
                        payload = await _grpcCipherService.CreateFailureResponse(encryptResult.UnwrapErr(), connectId,
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
        catch (OperationCanceledException ex)
        {
            Log.Information("[verification.flow.grpc.stream-cancelled] ConnectId {ConnectId}", connectId);
            Log.Debug(ex, "[verification.flow.grpc.stream-cancelled] ConnectId {ConnectId}", connectId);
        }
    }

    private static Ecliptix.IdentityAccess.Domain.Memberships.VerificationPurpose ConvertProtoPurposeToDomain(
        VerificationPurpose protoPurpose)
    {
        return protoPurpose switch
        {
            VerificationPurpose.Registration => Ecliptix.IdentityAccess.Domain.Memberships.VerificationPurpose.Registration,
            VerificationPurpose.Login => Ecliptix.IdentityAccess.Domain.Memberships.VerificationPurpose.Login,
            VerificationPurpose.PasswordRecovery => Ecliptix.IdentityAccess.Domain.Memberships.VerificationPurpose.SecureKeyRecovery,
            _ => Ecliptix.IdentityAccess.Domain.Memberships.VerificationPurpose.Unspecified
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
