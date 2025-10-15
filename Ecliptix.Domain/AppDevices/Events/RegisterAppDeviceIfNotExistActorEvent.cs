using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Protobuf.Device;

namespace Ecliptix.Domain.AppDevices.Events;

public record RegisterAppDeviceIfNotExistActorEvent(AppDevice AppDevice, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
