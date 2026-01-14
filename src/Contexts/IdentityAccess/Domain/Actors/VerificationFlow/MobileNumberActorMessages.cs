using Ecliptix.SharedKernel.Actors;

namespace Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow;

public record ExistsMobileNumberQuery(
    Guid MobileNumberId,
    Guid DeviceId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record ValidateMobileNumberCommand(
    string MobileNumber,
    string? RegionCode,
    Guid AppDeviceIdentifier,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetMobileNumberQuery(
    Guid MobileNumberIdentifier,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
