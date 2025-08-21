using System.Diagnostics;
using System.Text;
using Akka.Actor;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Observability;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Providers.Twilio;
using Ecliptix.Domain.Utilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Core.Api.Grpc.Base;

/// <summary>
/// Base class for authentication and verification gRPC services.
/// Provides OTP verification, SMS sending, and verification flow management.
/// </summary>
public abstract class AuthenticationServiceBase : ActorGrpcServiceBase<VerificationFlowManagerActor>
{
    protected readonly IActorRef VerificationFlowManagerActor;
    protected readonly ISmsProvider SmsProvider;

    protected AuthenticationServiceBase(
        ILogger logger,
        ActivitySource activitySource,
        ObjectPool<StringBuilder> stringBuilderPool,
        IGrpcCipherService cipherService,
        ObjectPool<EncryptionContext> encryptionContextPool,
        IEcliptixActorRegistry actorRegistry,
        ISmsProvider smsProvider)
        : base(logger, activitySource, stringBuilderPool, cipherService, encryptionContextPool, 
               actorRegistry, ActorIds.VerificationFlowManagerActor)
    {
        VerificationFlowManagerActor = actorRegistry.Get(ActorIds.VerificationFlowManagerActor);
        SmsProvider = smsProvider ?? throw new ArgumentNullException(nameof(smsProvider));
    }

    /// <summary>
    /// Initiates a verification flow with OTP generation and SMS sending
    /// </summary>
    protected async Task<Result<TResponse, VerificationFlowFailure>> InitiateVerificationFlowAsync<TRequest, TResponse>(
        TRequest request,
        uint connectId,
        string phoneNumber,
        CancellationToken cancellationToken)
        where TRequest : class
        where TResponse : class
    {
        using var activity = ActivitySource.StartActivity("InitiateVerificationFlow");
        activity?.SetTag("connect_id", connectId);
        activity?.SetTag("phone_number_length", phoneNumber?.Length ?? 0);

        try
        {
            Logger.LogDebug("Initiating verification flow for connect ID {ConnectId}", connectId);

            // Create verification flow initiation event  
            var initiateEvent = new InitiateVerificationFlowActorEvent(
                connectId,
                Guid.Empty, // PhoneNumberIdentifier - will be set by the actor
                Guid.Empty, // AppDeviceIdentifier - will be set by the actor  
                VerificationPurpose.Registration, // Default purpose
                InitiateVerificationRequest.Types.Type.SendOtp, // Default type
                null!, // ChannelWriter - will be set by concrete implementation
                "en-us" // Default culture
            );
            
            var result = await AskActorAsync<InitiateVerificationFlowActorEvent, Result<TResponse, VerificationFlowFailure>>(
                VerificationFlowManagerActor, initiateEvent, cancellationToken);

            if (result.IsOk)
            {
                activity?.SetTag("verification_initiated", true);
                Logger.LogInformation("Verification flow initiated successfully for connect ID {ConnectId}", connectId);
            }
            else
            {
                activity?.SetTag("verification_initiated", false);
                Logger.LogWarning("Failed to initiate verification flow for connect ID {ConnectId}: {Error}", 
                    connectId, result.UnwrapErr().Message);
            }

            return result;
        }
        catch (Exception ex)
        {
            activity?.SetTag("verification_initiated", false);
            Logger.LogError(ex, "Error initiating verification flow for connect ID {ConnectId}", connectId);
            return Result<TResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic($"Verification flow initiation failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Verifies an OTP code for a given verification flow
    /// </summary>
    protected async Task<Result<TResponse, VerificationFlowFailure>> VerifyOtpCodeAsync<TResponse>(
        string otpCode,
        uint connectId,
        string purpose,
        CancellationToken cancellationToken)
        where TResponse : class
    {
        using var activity = ActivitySource.StartActivity("VerifyOtpCode");
        activity?.SetTag("connect_id", connectId);
        activity?.SetTag("otp_length", otpCode?.Length ?? 0);
        activity?.SetTag("purpose", purpose);

        try
        {
            if (string.IsNullOrWhiteSpace(otpCode))
            {
                Logger.LogWarning("OTP verification attempted with empty code for connect ID {ConnectId}", connectId);
                return Result<TResponse, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.InvalidOtp("OTP code cannot be empty"));
            }

            Logger.LogDebug("Verifying OTP code for connect ID {ConnectId}, purpose: {Purpose}", connectId, purpose);

            var verifyEvent = new VerifyFlowActorEvent( connectId, otpCode,purpose);
            
            var result = await AskActorAsync<VerifyFlowActorEvent, Result<TResponse, VerificationFlowFailure>>(
                VerificationFlowManagerActor, verifyEvent, cancellationToken);

            if (result.IsOk)
            {
                activity?.SetTag("otp_verified", true);
                Logger.LogInformation("OTP verified successfully for connect ID {ConnectId}", connectId);
            }
            else
            {
                activity?.SetTag("otp_verified", false);
                Logger.LogWarning("OTP verification failed for connect ID {ConnectId}: {Error}", 
                    connectId, result.UnwrapErr().Message);
            }

            return result;
        }
        catch (Exception ex)
        {
            activity?.SetTag("otp_verified", false);
            Logger.LogError(ex, "Error verifying OTP for connect ID {ConnectId}", connectId);
            return Result<TResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic($"OTP verification failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Sends an SMS with retry logic and delivery tracking
    /// </summary>
    protected async Task<Result<SmsDeliveryResult, VerificationFlowFailure>> SendSmsAsync(
        string phoneNumber,
        string message,
        CancellationToken cancellationToken,
        int maxRetries = 3)
    {
        using var activity = ActivitySource.StartActivity("SendSms");
        activity?.SetTag("phone_number_length", phoneNumber?.Length ?? 0);
        activity?.SetTag("message_length", message?.Length ?? 0);
        activity?.SetTag("max_retries", maxRetries);

        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            try
            {
                activity?.SetTag("current_attempt", attempt);
                Logger.LogDebug("Sending SMS attempt {Attempt}/{MaxRetries}", attempt, maxRetries);

                var result = await SmsProvider.SendOtpAsync(phoneNumber!, message!);
                
                if (result.Status == SmsDeliveryStatus.Sent || result.Status == SmsDeliveryStatus.Delivered)
                {
                    activity?.SetTag("sms_sent", true);
                    activity?.SetTag("attempts_used", attempt);
                    Logger.LogInformation("SMS sent successfully on attempt {Attempt}", attempt);
                    return Result<SmsDeliveryResult, VerificationFlowFailure>.Ok(result);
                }

                if (attempt == maxRetries)
                {
                    activity?.SetTag("sms_sent", false);
                    Logger.LogError("SMS sending failed after {MaxRetries} attempts. Final status: {Status}", 
                        maxRetries, result.Status);
                    return Result<SmsDeliveryResult, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.SmsSendFailed($"SMS delivery failed: {result.Status}"));
                }

                // Wait before retry (exponential backoff)
                var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt - 1));
                Logger.LogWarning("SMS attempt {Attempt} failed with status {Status}, retrying in {Delay}ms", 
                    attempt, result.Status, delay.TotalMilliseconds);
                await Task.Delay(delay, cancellationToken);
            }
            catch (Exception ex) when (attempt < maxRetries)
            {
                Logger.LogWarning(ex, "SMS sending attempt {Attempt} failed with exception, retrying", attempt);
                var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt - 1));
                await Task.Delay(delay, cancellationToken);
            }
            catch (Exception ex)
            {
                activity?.SetTag("sms_sent", false);
                Logger.LogError(ex, "SMS sending failed after {MaxRetries} attempts", maxRetries);
                return Result<SmsDeliveryResult, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.SmsSendFailed($"SMS delivery failed: {ex.Message}"));
            }
        }

        // This shouldn't be reached, but included for completeness
        return Result<SmsDeliveryResult, VerificationFlowFailure>.Err(
            VerificationFlowFailure.SmsSendFailed("SMS delivery failed after all retry attempts"));
    }

    /// <summary>
    /// Manages verification flow cleanup on client disconnect
    /// </summary>
    protected void CleanupVerificationFlow(uint connectId, string reason = "Client disconnected")
    {
        using var activity = ActivitySource.StartActivity("CleanupVerificationFlow");
        activity?.SetTag("connect_id", connectId);
        activity?.SetTag("reason", reason);

        try
        {
            Logger.LogInformation("Cleaning up verification flow for connect ID {ConnectId}: {Reason}", connectId, reason);
            
            var cleanupEvent = new PrepareForTerminationMessage();
            TellActor(VerificationFlowManagerActor, cleanupEvent);
            
            activity?.SetTag("cleanup_sent", true);
        }
        catch (Exception ex)
        {
            activity?.SetTag("cleanup_sent", false);
            Logger.LogWarning(ex, "Failed to send cleanup message for connect ID {ConnectId}", connectId);
        }
    }
}