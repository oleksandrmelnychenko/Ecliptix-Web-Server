using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.MobileNumber;

public record EnsureMobileNumberActorEvent(
    string MobileNumber,
    string? RegionCode,
    Guid AppDeviceIdentifier,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
