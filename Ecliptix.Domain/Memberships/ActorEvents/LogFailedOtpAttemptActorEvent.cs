using System;
using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record LogFailedOtpAttemptActorEvent(
    Guid OtpUniqueId,
    string FailureReason,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
