using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.MobileNumber;

public record EnsureMobileNumberActorEvent(
    string MobileNumber,
    string? RegionCode,
    Guid AppDeviceIdentifier,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
