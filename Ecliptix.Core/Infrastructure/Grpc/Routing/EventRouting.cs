using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

public sealed record EventRoute(
    TransportEventType EventType,
    EventContext Context,
    Func<ReadOnlyMemory<byte>, object> Deserialize,
    Func<object, ReadOnlyMemory<byte>> Serialize,
    Func<object, EventMetadata, CancellationToken, Task<Result<object, FailureBase>>> HandleAsync,
    bool IdempotencyRequired);

public interface IEventRouteProvider
{
    bool TryGetRoute(TransportEventType eventType, out EventRoute route);
}

public interface IEventRouteResolver
{
    bool TryGetRoute(TransportEventType eventType, out EventRoute route);
}

public sealed class EventRouteResolver(IEnumerable<IEventRouteProvider>? providers) : IEventRouteResolver
{
    private readonly IEnumerable<IEventRouteProvider> _providers = providers ?? [];

    public bool TryGetRoute(TransportEventType eventType, out EventRoute route)
    {
        foreach (IEventRouteProvider provider in _providers)
        {
            if (provider.TryGetRoute(eventType, out route))
            {
                return true;
            }
        }

        route = null!;
        return false;
    }
}

public interface IEventHandler<in T>
{
    Task<Result<object, FailureBase>> HandleAsync(T message, EventMetadata metadata, CancellationToken cancellationToken);
}
