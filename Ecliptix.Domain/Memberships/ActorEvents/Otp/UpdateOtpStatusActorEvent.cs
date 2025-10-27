using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Otp;

public record UpdateOtpStatusActorEvent(
    Guid OtpIdentified,
    OtpStatus Status,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
