using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record EnsureMobileNumberActorEvent(
    string MobileNumber,
    string? RegionCode,
    Guid AppDeviceIdentifier,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
