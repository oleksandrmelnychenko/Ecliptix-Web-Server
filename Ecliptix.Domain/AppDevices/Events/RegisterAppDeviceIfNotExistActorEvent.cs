using Ecliptix.Protobuf.Device;

namespace Ecliptix.Domain.AppDevices.Events;

public record RegisterAppDeviceIfNotExistActorEvent(AppDevice AppDevice);