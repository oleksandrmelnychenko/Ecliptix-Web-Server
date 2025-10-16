using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record UpdateOtpStatusActorEvent(
    Guid OtpIdentified,
    VerificationFlowStatus Status,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
