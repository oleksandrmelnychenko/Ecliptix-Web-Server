using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.ActorEvents.Account;

public record GetAccountProfileByIdEvent(
    Guid AccountId,
    CancellationToken CancellationToken
) : ICancellableActorEvent;

public record GetAccountProfileByIdResult(Result<Option<AccountProfileInfo>, FailureBase> Result);

