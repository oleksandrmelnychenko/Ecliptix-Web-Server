using System;
using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record GetOtpAttemptCountActorEvent(
    Guid OtpUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
