using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.SharedKernel;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents;

public abstract record ProfileSearchCriteria;
public record SearchByMobile(string MobileNumber) : ProfileSearchCriteria;
public record SearchById(Guid AccountId) : ProfileSearchCriteria;

public record CheckProfileNameAvailabilityEvent(
    string ProfileName,
    CancellationToken CancellationToken
) : ICancellableActorEvent;

public record GetAccountProfileActorEvent(
    Guid CurrentAccountId,
    ProfileSearchCriteria Criteria,
    CancellationToken CancellationToken
) : ICancellableActorEvent;

public record GetAccountProfileResult(Result<Option<AccountProfileInfo>, FailureBase> Result);

public record UpdateAccountProfileEvent(
    Guid AccountId,
    string ProfileName,
    string DisplayName,
    CancellationToken CancellationToken
) : ICancellableActorEvent;
