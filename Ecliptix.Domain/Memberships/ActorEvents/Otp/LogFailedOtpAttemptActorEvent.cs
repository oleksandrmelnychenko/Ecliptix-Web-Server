using System;
using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Otp;

public record LogFailedOtpAttemptActorEvent(
    Guid OtpUniqueId,
    string FailureReason,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
