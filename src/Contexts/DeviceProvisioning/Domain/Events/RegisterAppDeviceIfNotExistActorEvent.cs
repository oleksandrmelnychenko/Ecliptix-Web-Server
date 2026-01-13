using Ecliptix.Protobuf.Device;
using Ecliptix.SharedKernel.Actors;

namespace Ecliptix.DeviceProvisioning.Domain.Events;

public record RegisterAppDeviceIfNotExistActorEvent(
    Device AppDevice,
    CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
