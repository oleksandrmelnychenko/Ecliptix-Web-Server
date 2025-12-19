using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.ActorEvents.AccountProfile;

public record CheckProfileNameAvailabilityEvent(
    string ProfileName,
    CancellationToken CancellationToken
) : ICancellableActorEvent;


public record CheckProfileNameAvailabilityResult(Result<bool, FailureBase> Result);
