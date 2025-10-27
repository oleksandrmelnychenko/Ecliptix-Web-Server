using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Otp;

public record RequestResendOtpActorEvent(
    Guid FlowUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
