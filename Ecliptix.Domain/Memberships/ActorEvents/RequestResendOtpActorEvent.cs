using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record RequestResendOtpActorEvent(
    Guid FlowUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
