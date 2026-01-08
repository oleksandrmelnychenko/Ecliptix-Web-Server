using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.SharedKernel;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.AccountProfile;

public abstract record ProfileSearchCriteria;
public record SearchByMobile(string MobileNumber) : ProfileSearchCriteria;
public record SearchById(Guid AccountId) : ProfileSearchCriteria;

public record GetAccountProfileActorEvent(
    Guid CurrentAccountId,
    ProfileSearchCriteria Criteria,
    CancellationToken CancellationToken
) : ICancellableActorEvent;

public record GetAccountProfileResult(Result<Option<AccountProfileInfo>, FailureBase> Result);
