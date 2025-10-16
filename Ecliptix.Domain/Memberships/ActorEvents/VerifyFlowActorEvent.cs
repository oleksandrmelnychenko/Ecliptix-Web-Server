using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record VerifyFlowActorEvent(
    uint ConnectId,
    string OneTimePassword,
    string CultureName,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
