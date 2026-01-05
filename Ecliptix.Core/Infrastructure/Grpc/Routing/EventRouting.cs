using System.Diagnostics.CodeAnalysis;
using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

public sealed record EventRoute(
    string EventType,
    string Context,
    Func<ReadOnlyMemory<byte>, object> Deserialize,
    Func<object, ReadOnlyMemory<byte>> Serialize,
    Func<object, EventMetadata, CancellationToken, Task<Result<object, FailureBase>>> HandleAsync);

public interface IEventRouteProvider
{
    bool TryGetRoute(string eventType, [NotNullWhen(true)] out EventRoute route);
}

public interface IEventRouteResolver
{
    bool TryGetRoute(string eventType, [NotNullWhen(true)] out EventRoute route);
}

/// <summary>
/// Resolves event routes by querying all registered providers until a match is found.
/// </summary>
public sealed class EventRouteResolver : IEventRouteResolver
{
    private readonly IEnumerable<IEventRouteProvider> _providers;

    public EventRouteResolver(IEnumerable<IEventRouteProvider> providers)
    {
        _providers = providers ?? Enumerable.Empty<IEventRouteProvider>();
    }

    public bool TryGetRoute(string eventType, out EventRoute route)
    {
        foreach (IEventRouteProvider provider in _providers)
        {
            if (provider.TryGetRoute(eventType, out route))
            {
                return true;
            }
        }

        route = default!;
        return false;
    }
}

[AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
public sealed class EventRouteAttribute : Attribute
{
    public string EventType { get; }
    public string Context { get; }

    public EventRouteAttribute(string eventType, string context)
    {
        EventType = eventType;
        Context = context;
    }
}

public interface IEventHandler<in T>
{
    Task<Result<object, FailureBase>> HandleAsync(T message, EventMetadata metadata, CancellationToken cancellationToken);
}
