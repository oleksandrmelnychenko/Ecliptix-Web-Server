using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;
using Ecliptix.SharedKernel;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.AccountProfile;

public record CheckProfileNameAvailabilityEvent(
    string ProfileName,
    CancellationToken CancellationToken
) : ICancellableActorEvent;

public record CheckProfileNameAvailabilityResult(Result<bool, FailureBase> Result);
