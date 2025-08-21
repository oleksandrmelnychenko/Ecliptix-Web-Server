using System.Diagnostics;
using System.Text;
using Akka.Actor;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Observability;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Domain.Utilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;

namespace Ecliptix.Core.Api.Grpc.Base;

/// <summary>
/// Base class for membership-related gRPC services.
/// Provides membership-specific operations like OPAQUE protocol handling and phone validation.
/// </summary>
public abstract class MembershipServiceBase : ActorGrpcServiceBase<IActorRef>
{
    protected readonly IActorRef MembershipActor;
    protected readonly IPhoneNumberValidator PhoneNumberValidator;

    protected MembershipServiceBase(
        ILogger logger,
        ActivitySource activitySource,
        ObjectPool<StringBuilder> stringBuilderPool,
        IGrpcCipherService cipherService,
        ObjectPool<EncryptionContext> encryptionContextPool,
        IEcliptixActorRegistry actorRegistry,
        IPhoneNumberValidator phoneNumberValidator)
        : base(logger, activitySource, stringBuilderPool, cipherService, encryptionContextPool, 
               actorRegistry, ActorIds.MembershipActor)
    {
        MembershipActor = actorRegistry.Get(ActorIds.MembershipActor);
        PhoneNumberValidator = phoneNumberValidator ?? throw new ArgumentNullException(nameof(phoneNumberValidator));
    }

    /// <summary>
    /// Validates a phone number with culture-specific formatting
    /// </summary>
    protected Result<PhoneNumberValidationResult, VerificationFlowFailure> ValidatePhoneNumber(
        string phoneNumber, string cultureName)
    {
        using var activity = ActivitySource.StartActivity("ValidatePhoneNumber");
        activity?.SetTag("phone_number_length", phoneNumber?.Length ?? 0);
        activity?.SetTag("culture", cultureName);

        try
        {
            var result = PhoneNumberValidator.ValidatePhoneNumber(phoneNumber!, cultureName);
            
            activity?.SetTag("validation_success", result.IsOk);
            if (result.IsOk)
            {
                var validationResult = result.Unwrap();
                activity?.SetTag("is_valid", validationResult.IsValid);
                activity?.SetTag("is_mobile", validationResult.MobileStatus == MobileCheckStatus.IsMobile);
            }

            return result;
        }
        catch (Exception ex)
        {
            activity?.SetTag("validation_success", false);
            Logger.LogError(ex, "Phone number validation failed for culture {Culture}", cultureName);
            return Result<PhoneNumberValidationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Phone number validation failed"));
        }
    }

    /// <summary>
    /// Executes OPAQUE protocol operations with the membership actor
    /// </summary>
    protected async Task<Result<TResponse, VerificationFlowFailure>> ExecuteOpaqueOperationAsync<TRequest, TResponse>(
        TRequest request,
        string operationName,
        CancellationToken cancellationToken)
        where TRequest : class
        where TResponse : class
    {
        using var activity = ActivitySource.StartActivity($"OpaqueOperation.{operationName}");
        activity?.SetTag("request_type", typeof(TRequest).Name);

        try
        {
            Logger.LogDebug("Executing OPAQUE operation {OperationName} with request type {RequestType}", 
                operationName, typeof(TRequest).Name);

            // Create appropriate actor event based on request type
            var actorEvent = CreateMembershipActorEvent(request, operationName);
            
            var result = await AskActorAsync<object, Result<TResponse, VerificationFlowFailure>>(
                MembershipActor, actorEvent, cancellationToken);

            activity?.SetTag("success", result.IsOk);
            
            if (result.IsOk)
            {
                Logger.LogDebug("OPAQUE operation {OperationName} completed successfully", operationName);
            }
            else
            {
                Logger.LogWarning("OPAQUE operation {OperationName} failed: {Error}", 
                    operationName, result.UnwrapErr().Message);
            }

            return result;
        }
        catch (Exception ex)
        {
            activity?.SetTag("success", false);
            Logger.LogError(ex, "OPAQUE operation {OperationName} encountered an error", operationName);
            return Result<TResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic($"OPAQUE operation {operationName} failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Creates the appropriate actor event based on request type and operation
    /// </summary>
    private object CreateMembershipActorEvent<TRequest>(TRequest request, string operationName)
    {
        // This would map to specific actor events based on the operation type
        // For now, return a generic event - this should be implemented based on actual actor events
        return operationName switch
        {
            "SignInInit" => new SignInMembershipActorEvent("", new OpaqueSignInInitRequest(), "en-us"),
            "RegistrationInit" => new CreateMembershipActorEvent(0, Guid.Empty, Guid.Empty, Membership.Types.CreationStatus.OtpVerified),
            _ => throw new ArgumentException($"Unknown OPAQUE operation: {operationName}")
        };
    }

    /// <summary>
    /// Handles validation failures with appropriate user-facing messages
    /// </summary>
    protected TResponse CreateValidationFailureResponse<TResponse>(
        VerificationFlowFailure failure, 
        Func<string, TResponse> responseFactory)
        where TResponse : class
    {
        using var activity = ActivitySource.StartActivity("CreateValidationFailureResponse");
        activity?.SetTag("failure_type", failure.GetType().Name);
        activity?.SetTag("is_user_facing", failure.IsUserFacing);

        if (failure.IsUserFacing)
        {
            Logger.LogInformation("Returning user-facing validation failure: {Message}", failure.Message);
            return responseFactory(failure.Message);
        }

        Logger.LogWarning("Returning generic validation failure for non-user-facing error: {Message}", failure.Message);
        return responseFactory("Invalid request");
    }

    /// <summary>
    /// Validates membership operation parameters
    /// </summary>
    protected bool ValidateMembershipOperation(string phoneNumber, out string normalizedPhoneNumber)
    {
        normalizedPhoneNumber = string.Empty;
        
        if (string.IsNullOrWhiteSpace(phoneNumber))
        {
            Logger.LogWarning("Membership operation attempted with empty phone number");
            return false;
        }

        // Additional validation logic can be added here
        normalizedPhoneNumber = phoneNumber.Trim();
        return true;
    }
}