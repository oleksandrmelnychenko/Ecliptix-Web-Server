using System;
using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Otp;

public record GetOtpAttemptCountActorEvent(
    Guid OtpUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
