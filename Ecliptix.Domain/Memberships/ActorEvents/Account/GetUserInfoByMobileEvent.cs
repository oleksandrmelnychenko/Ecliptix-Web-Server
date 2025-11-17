using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.ActorEvents.Account;

public record GetUserInfoByMobileEvent(string MobileNumber, CancellationToken CancellationToken) : ICancellableActorEvent;

public record GetUserInfoByMobileResult(Result<Option<UserInfo>, FailureBase> Result);
