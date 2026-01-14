using Ecliptix.Protobuf.Transport.Common;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

[AttributeUsage(AttributeTargets.Method, Inherited = false)]
internal sealed class EventRouteAttribute(
    TransportEventType eventType,
    EventContext context,
    DeliveryKind deliveryKind = DeliveryKind.Unary) : Attribute
{
    public TransportEventType EventType { get; } = eventType;

    public EventContext Context { get; } = context;

    public DeliveryKind DeliveryKind { get; } = deliveryKind;

    public bool IdempotencyRequired { get; init; }

    public bool RequiresDeviceId { get; init; }

    public bool RequiresApplicationInstanceId { get; init; }
}
