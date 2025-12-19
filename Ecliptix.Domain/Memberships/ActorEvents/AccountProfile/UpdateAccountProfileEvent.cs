using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.ActorEvents.AccountProfile;

public record UpdateAccountProfileEvent(
    Guid AccountId,
    string ProfileName,
    string DisplayName,
    CancellationToken CancellationToken
) : ICancellableActorEvent;

public record UpdateAccountProfileResult(Result<AccountProfileInfo, FailureBase> Result);
