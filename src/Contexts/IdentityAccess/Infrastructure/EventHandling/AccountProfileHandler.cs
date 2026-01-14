using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Actors.AccountProfile;
using Ecliptix.IdentityAccess.Domain.Actors.Membership;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
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

public sealed class AccountProfileHandler(
    IEcliptixActorRegistry actorRegistry,
    IGrpcCipherService grpcCipherService,
    IOptions<SecurityConfiguration> securityConfig)
{
    private readonly GrpcSecurityService _service = new(grpcCipherService, securityConfig);
    private readonly IActorRef _accountActor = actorRegistry.Get(ActorIds.AccountProfileActor);

    public async Task<SecureEnvelope> CheckProfileNameAvailability(SecureEnvelope request, ServerCallContext context)
    {
        return await _service
            .ExecuteEncryptedOperationAsync<ProfileNameAvailabilityRequest, ProfileNameAvailabilityResponse>(
                request, context,
                async (message, _, _, cancellationToken) =>
                {
                    ExistsProfileNameQuery evt = new(message.ProfileName, cancellationToken);

                    Task<Result<bool, AccountProfileFailure>> task =
                        _accountActor.Ask<Result<bool, AccountProfileFailure>>(
                            evt,
                            TimeoutConfiguration.Actor.AskTimeout);

                    Result<bool, AccountProfileFailure> result =
                        await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                    if (result.IsErr)
                    {
                        return Result<ProfileNameAvailabilityResponse, FailureBase>.Err(result.UnwrapErr());
                    }

                    bool isAvailable = result.Unwrap();

                    return Result<ProfileNameAvailabilityResponse, FailureBase>.Ok(
                        new ProfileNameAvailabilityResponse
                        {
                            IsAvailable = isAvailable, Reason = isAvailable ? "Available" : "Taken"
                        });
                });
    }

    public async Task<SecureEnvelope> CreateOrUpdateProfile(SecureEnvelope request, ServerCallContext context)
    {
        return await _service
            .ExecuteEncryptedOperationAsync<ProfileUpsertRequest, ProfileUpsertResponse>(
                request, context,
                async (message, _, _, cancellationToken) =>
                {
                    Guid accountId = Helpers.FromByteStringToGuid(message.AccountId);

                    UpdateAccountProfileCommand evt = new(
                        accountId,
                        message.ProfileName,
                        message.DisplayName,
                        cancellationToken);

                    Task<Result<AccountProfileInfo, AccountProfileFailure>> task =
                        _accountActor.Ask<Result<AccountProfileInfo, AccountProfileFailure>>(
                            evt,
                            TimeoutConfiguration.Actor.AskTimeout);

                    Result<AccountProfileInfo, AccountProfileFailure> result =
                        await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                    if (result.IsErr)
                    {
                        return Result<ProfileUpsertResponse, FailureBase>.Err(result.UnwrapErr());
                    }

                    AccountProfileInfo info = result.Unwrap();

                    return Result<ProfileUpsertResponse, FailureBase>.Ok(
                        new ProfileUpsertResponse
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
        return await _service.ExecuteEncryptedOperationAsync<ProfileLookupRequest, ProfileLookupResponse>(
            request,
            context,
            async (message, _, _, cancellationToken) =>
            {
                Guid currentAccountId = Helpers.FromByteStringToGuid(message.CurrentAccountId);

                ProfileSearchCriteria criteria = message.SearchCriteriaCase switch
                {
                    ProfileLookupRequest.SearchCriteriaOneofCase.ByMobileNumber =>
                        new SearchByMobile(message.ByMobileNumber),

                    ProfileLookupRequest.SearchCriteriaOneofCase.ByAccountId =>
                        new SearchById(Helpers.FromByteStringToGuid(message.ByAccountId)),

                    _ => throw new RpcException(new Status(StatusCode.InvalidArgument, "Search criteria not specified"))
                };

                GetAccountProfileQuery actorEvent = new(currentAccountId, criteria, cancellationToken);

                Task<Result<Option<AccountProfileInfo>, AccountProfileFailure>> task =
                    _accountActor.Ask<Result<Option<AccountProfileInfo>, AccountProfileFailure>>(
                        actorEvent,
                        TimeoutConfiguration.Actor.AskTimeout);

                Result<Option<AccountProfileInfo>, AccountProfileFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                if (result.IsErr)
                {
                    return Result<ProfileLookupResponse, FailureBase>.Err(result.UnwrapErr());
                }

                Option<AccountProfileInfo> profileInfoOpt = result.Unwrap();

                ProfileLookupResponse response = new();

                if (!profileInfoOpt.IsSome)
                {
                    return Result<ProfileLookupResponse, FailureBase>.Ok(response);
                }

                AccountProfileInfo profileInfo = profileInfoOpt.Value!;

                response.Profile = new AccountProfile
                {
                    ProfileId = Helpers.GuidToByteString(profileInfo.ProfileId),
                    AccountId = Helpers.GuidToByteString(profileInfo.AccountId),
                    ProfileName = profileInfo.ProfileName,
                    DisplayName = profileInfo.DisplayName
                };

                return Result<ProfileLookupResponse, FailureBase>.Ok(response);
            });
    }
}
