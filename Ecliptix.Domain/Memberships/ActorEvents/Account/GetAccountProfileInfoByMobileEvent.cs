using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.ActorEvents.Account;

public record GetAccountProfileInfoByMobileEvent(string MobileNumber, Guid CurrentAccountId, CancellationToken CancellationToken) : ICancellableActorEvent;

public record GetAccountProfileInfoByMobileResult(Result<Option<AccountProfileInfo>, FailureBase> Result);
