using System.Diagnostics;
using System.Threading;
using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.Core.Api.Grpc.Base;
using System.Globalization;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.MobileNumberValidation;
using Ecliptix.Domain.Memberships.Instrumentation;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Membership;
using Google.Protobuf;
using Grpc.Core;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Serilog;

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

                        using CancellationTokenSource linkedCts =
                            CancellationTokenSource.CreateLinkedTokenSource(ct, context.CancellationToken);

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

                        Result<Unit, VerificationFlowFailure> initiationResult = await _verificationFlowManagerActor
                            .Ask<Result<Unit, VerificationFlowFailure>>(
                                new InitiateVerificationFlowActorEvent(
                                    connectId,
                                    Helpers.FromByteStringToGuid(initiateRequest.MobileNumberIdentifier),
                                    Helpers.FromByteStringToGuid(initiateRequest.AppDeviceIdentifier),
                                    initiateRequest.Purpose,
                                    initiateRequest.Type,
                                    channel.Writer,
                                    _cultureName,
                                    flowActivity?.Context ?? Activity.Current?.Context ?? default,
                                    linkedCts.Token
                                ), linkedCts.Token);

                        if (initiationResult.IsErr)
                        {
                            flowActivity?.Dispose();
                            return Result<Unit, VerificationFlowFailure>.Err(initiationResult.UnwrapErr());
                        }

                        try
                        {
                            await streamingTask.ConfigureAwait(false);
                            Log.Information("[verification.flow.grpc.completed] ConnectId {ConnectId}", connectId);
                            flowActivity?.SetTag("verification.stream.completed", true);
                        }
                        catch (OperationCanceledException)
                        {
                            Log.Information("[verification.flow.grpc.cancelled] ConnectId {ConnectId}", connectId);
                            flowActivity?.SetTag("verification.stream.completed", false);
                            throw;
                        }
                        finally
                        {
                            flowActivity?.Dispose();
                        }

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
                        Helpers.FromByteStringToGuid(message.AppDeviceIdentifier),
                        ct);

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
                        phoneValidationResult.DetectedRegion,
                        ct);

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

    public override async Task<SecureEnvelope> CheckMembershipStatus(SecureEnvelope request, ServerCallContext context) =>
        await _baseService.ExecuteEncryptedOperationAsync<CheckMembershipStatusRequest, CheckMembershipStatusResponse>(
            request, context,
            async (message, _, ct) =>
            {
                CheckMembershipStatusActorEvent actorEvent = new(
                    Helpers.FromByteStringToGuid(message.MobileNumberIdentifier),
                    ct);

                Result<string, VerificationFlowFailure> checkResult = await _verificationFlowManagerActor
                    .Ask<Result<string, VerificationFlowFailure>>(actorEvent, ct);

                return checkResult.Match(
                    status => Result<CheckMembershipStatusResponse, FailureBase>.Ok(new CheckMembershipStatusResponse
                    {
                        Status = status
                    }),
                    Result<CheckMembershipStatusResponse, FailureBase>.Err
                );
            });

    public override async Task<SecureEnvelope> VerifyOtp(SecureEnvelope request, ServerCallContext context) =>
        await _baseService.ExecuteEncryptedOperationAsync<VerifyCodeRequest, VerifyCodeResponse>(request, context,
            async (message, _, ct) =>
            {
                VerifyFlowActorEvent actorEvent = new(message.StreamConnectId, message.Code, _cultureName, ct);
                actorEvent = actorEvent with { CancellationToken = ct };

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
            Log.Debug("[verification.flow.grpc.stream-cancelled] ConnectId {ConnectId}", connectId);
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
