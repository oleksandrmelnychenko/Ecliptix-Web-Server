using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;
using Google.Protobuf;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

public sealed record EventRoute(
    EventContext Context,
    Func<ReadOnlyMemory<byte>, IMessage> Deserialize,
    Func<IMessage, ReadOnlyMemory<byte>> Serialize,
    Func<IMessage, EventMetadata, CancellationToken, Task<Result<IMessage, FailureBase>>> HandleAsync,
    bool IdempotencyRequired);

public interface IEventRouteResolver
{
    bool TryGetRoute(TransportEventType eventType, out EventRoute route);
}
