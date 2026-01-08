using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.SharedKernel;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.AccountProfile;

public record UpdateAccountProfileEvent(
    Guid AccountId,
    string ProfileName,
    string DisplayName,
    CancellationToken CancellationToken
) : ICancellableActorEvent;

public record UpdateAccountProfileResult(Result<AccountProfileInfo, FailureBase> Result);
