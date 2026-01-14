using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;

namespace Ecliptix.IdentityAccess.Domain.Actors.AccountProfile;

public abstract record ProfileSearchCriteria;
public record SearchByMobile(string MobileNumber) : ProfileSearchCriteria;
public record SearchById(Guid AccountId) : ProfileSearchCriteria;

public record ExistsProfileNameQuery(
    string ProfileName,
    CancellationToken CancellationToken
) : ICancellableActorEvent;

public record GetAccountProfileQuery(
    Guid CurrentAccountId,
    ProfileSearchCriteria Criteria,
    CancellationToken CancellationToken
) : ICancellableActorEvent;

public record GetAccountProfileResponse(Result<Option<AccountProfileInfo>, FailureBase> Result);

public record UpdateAccountProfileCommand(
    Guid AccountId,
    string ProfileName,
    string DisplayName,
    CancellationToken CancellationToken
) : ICancellableActorEvent;
