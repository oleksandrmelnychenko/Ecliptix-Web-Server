using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

public sealed record EventRoute(
    EventContext Context,
    DeliveryKind DeliveryKind,
    Func<ReadOnlyMemory<byte>, IMessage> Deserialize,
    Func<IMessage, ReadOnlyMemory<byte>> Serialize,
    Func<IMessage, EventMetadata, CancellationToken, Task<Result<IMessage, FailureBase>>>? HandleUnaryAsync,
    Func<IMessage, EventMetadata, IServerStreamWriter<EventEnvelope>, CancellationToken, Task>? HandleServerStreamAsync,
    Func<IAsyncEnumerable<IMessage>, EventMetadata, CancellationToken, Task<Result<IMessage, FailureBase>>>? HandleClientStreamAsync,
    Func<IAsyncEnumerable<IMessage>, EventMetadata, IServerStreamWriter<EventEnvelope>, CancellationToken, Task>? HandleBidiStreamAsync,
    bool IdempotencyRequired,
    bool RequiresDeviceId,
    bool RequiresApplicationInstanceId);

public interface IEventRouteResolver
{
    bool TryGetRoute(TransportEventType eventType, out EventRoute route);
}
