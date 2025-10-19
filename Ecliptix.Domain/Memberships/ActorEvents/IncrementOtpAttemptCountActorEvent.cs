using System;
using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record IncrementOtpAttemptCountActorEvent(
    Guid OtpUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
