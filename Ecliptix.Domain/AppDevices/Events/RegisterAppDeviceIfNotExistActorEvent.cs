using Ecliptix.Protobuf.AppDevice;

namespace Ecliptix.Domain.AppDevices.Events;

public record RegisterAppDeviceIfNotExistActorEvent(AppDevice AppDevice);