using Ecliptix.SharedKernel.Actors;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents;

public record CheckMobileNumberAvailabilityActorEvent(
    Guid MobileNumberId,
    Guid DeviceId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record EnsureMobileNumberActorEvent(
    string MobileNumber,
    string? RegionCode,
    Guid AppDeviceIdentifier,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetMobileNumberActorEvent(
    Guid MobileNumberIdentifier,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
