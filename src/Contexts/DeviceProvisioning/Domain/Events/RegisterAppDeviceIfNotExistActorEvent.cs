using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Protobuf.Device;

namespace Ecliptix.DeviceProvisioning.Domain.Events;

public record RegisterAppDeviceIfNotExistActorEvent(
    Device AppDevice,
    CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
