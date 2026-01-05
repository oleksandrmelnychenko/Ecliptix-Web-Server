using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.AccountProfile;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Protobuf.Account;
using Ecliptix.Protobuf.Common;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Grpc;
using Ecliptix.SharedKernel.Grpc.Utilities.CipherPayloadHandler;
using Grpc.Core;
using Microsoft.Extensions.Options;
using Status = Grpc.Core.Status;

namespace Ecliptix.IdentityAccess.Infrastructure.EventHandling;

/// <summary>
/// Internal command handler for account profiles (used via gateway/internal).
/// </summary>
public sealed class AccountProfileHandler
{
    private readonly GrpcSecurityService _service;
    private readonly IActorRef _accountActor;
    private readonly SecurityConfiguration _securityConfig;

    public AccountProfileHandler(
        IEcliptixActorRegistry actorRegistry,
        IGrpcCipherService grpcCipherService,
        IOptions<SecurityConfiguration> securityConfig)
    {
        _service = new GrpcSecurityService(grpcCipherService, securityConfig);
        _securityConfig = securityConfig.Value;

        _accountActor = actorRegistry.Get(ActorIds.AccountProfileActor);
    }

    public async Task<SecureEnvelope> CheckProfileNameAvailability(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<CheckProfileNameAvailabilityRequest, CheckProfileNameAvailabilityResponse>(
            request, context,
            async (message, _, _, cancellationToken) =>
            {
                CheckProfileNameAvailabilityEvent evt = new(message.ProfileName, cancellationToken);

                Task<Result<bool, AccountProfileFailure>> task = _accountActor.Ask<Result<bool, AccountProfileFailure>>(
                    evt,
                    TimeoutConfiguration.Actor.AskTimeout);

                Result<bool, AccountProfileFailure> result = await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                if (result.IsErr)
                {
                    return Result<CheckProfileNameAvailabilityResponse, FailureBase>.Err(result.UnwrapErr());
                }

                bool isAvailable = result.Unwrap();

                return Result<CheckProfileNameAvailabilityResponse, FailureBase>.Ok(
                    new CheckProfileNameAvailabilityResponse
                    {
                        IsAvailable = isAvailable,
                        Reason = isAvailable ? "Available" : "Taken"
                    });
            });
    }

    public async Task<SecureEnvelope> CreateOrUpdateProfile(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<CreateOrUpdateProfileRequest, CreateOrUpdateProfileResponse>(
            request, context,
            async (message, _, _, cancellationToken) =>
            {
                Guid accountId = Helpers.FromByteStringToGuid(message.AccountId);

                UpdateAccountProfileEvent evt = new(
                    accountId,
                    message.ProfileName,
                    message.DisplayName,
                    cancellationToken);

                Task<Result<AccountProfileInfo, AccountProfileFailure>> task = _accountActor.Ask<Result<AccountProfileInfo, AccountProfileFailure>>(
                    evt,
                    TimeoutConfiguration.Actor.AskTimeout);

                Result<AccountProfileInfo, AccountProfileFailure> result = await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                if (result.IsErr)
                {
                    return Result<CreateOrUpdateProfileResponse, FailureBase>.Err(result.UnwrapErr());
                }

                AccountProfileInfo info = result.Unwrap();

                return Result<CreateOrUpdateProfileResponse, FailureBase>.Ok(
                    new CreateOrUpdateProfileResponse
                    {
                        IsSuccess = true,
                        Profile = new AccountProfile
                        {
                            AccountId = Helpers.GuidToByteString(info.AccountId),
                            ProfileId = Helpers.GuidToByteString(info.ProfileId),
                            ProfileName = info.ProfileName,
                            DisplayName = info.DisplayName
                        }
                    });
            });
    }

     public async Task<SecureEnvelope> GetAccountProfile(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<GetAccountProfileRequest, GetAccountProfileResponse>(
            request,
            context,
            async (message, _, _, cancellationToken) =>
            {
                Guid currentAccountId = Helpers.FromByteStringToGuid(message.CurrentAccountId);

                ProfileSearchCriteria criteria = message.SearchCriteriaCase switch
                {
                    GetAccountProfileRequest.SearchCriteriaOneofCase.ByMobileNumber =>
                        new SearchByMobile(message.ByMobileNumber),

                    GetAccountProfileRequest.SearchCriteriaOneofCase.ByAccountId =>
                        new SearchById(Helpers.FromByteStringToGuid(message.ByAccountId)),

                    _ => throw new RpcException(new Status(StatusCode.InvalidArgument, "Search criteria not specified"))
                };

                GetAccountProfileActorEvent actorEvent = new(currentAccountId, criteria, cancellationToken);

                Task<Result<Option<AccountProfileInfo>, AccountProfileFailure>> task =
                    _accountActor.Ask<Result<Option<AccountProfileInfo>, AccountProfileFailure>>(
                        actorEvent,
                        TimeoutConfiguration.Actor.AskTimeout);

                Result<Option<AccountProfileInfo>, AccountProfileFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                if (result.IsErr)
                {
                    return Result<GetAccountProfileResponse, FailureBase>.Err(result.UnwrapErr());
                }

                Option<AccountProfileInfo> profileInfoOpt = result.Unwrap();

                GetAccountProfileResponse response = new();

                if (profileInfoOpt.IsSome)
                {
                    AccountProfileInfo profileInfo = profileInfoOpt.Value!;

                    response.Profile = new AccountProfile
                    {
                        ProfileId = Helpers.GuidToByteString(profileInfo.ProfileId),
                        AccountId = Helpers.GuidToByteString(profileInfo.AccountId),
                        ProfileName = profileInfo.ProfileName,
                        DisplayName = profileInfo.DisplayName
                    };
                }

                return Result<GetAccountProfileResponse, FailureBase>.Ok(response);
            });
    }
}
