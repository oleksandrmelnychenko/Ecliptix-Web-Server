using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;
using Google.Protobuf;
using Microsoft.Extensions.DependencyInjection;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

/// <summary>
/// Helper base class to register protobuf-backed event routes without switch statements.
/// </summary>
public abstract class ProtobufEventRouteProvider : IEventRouteProvider
{
    private readonly IServiceProvider _services;
    private readonly Dictionary<string, EventRoute> _routes = new(StringComparer.OrdinalIgnoreCase);

    protected ProtobufEventRouteProvider(IServiceProvider services)
    {
        _services = services;
    }

    protected void Register<TMessage>(string eventType, string context, MessageParser<TMessage> parser,
        Func<IServiceProvider, TMessage, EventMetadata, CancellationToken, Task<Result<object, FailureBase>>> handler,
        bool idempotencyRequired = false)
        where TMessage : class, IMessage<TMessage>
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventType);
        ArgumentException.ThrowIfNullOrWhiteSpace(context);
        ArgumentNullException.ThrowIfNull(parser);
        ArgumentNullException.ThrowIfNull(handler);

        _routes[eventType] = new EventRoute(
            eventType,
            context,
            Deserialize,
            Serialize,
            HandleAsync,
            idempotencyRequired);

        object Deserialize(ReadOnlyMemory<byte> payload)
        {
            return parser.ParseFrom(payload.Span);
        }

        ReadOnlyMemory<byte> Serialize(object value)
        {
            if (value is not IMessage message)
            {
                throw new InvalidOperationException($"Response for {eventType} must implement IMessage");
            }
            return message.ToByteArray();
        }

        Task<Result<object, FailureBase>> HandleAsync(object value, EventMetadata metadata,
            CancellationToken cancellationToken)
        {
            if (value is not TMessage message)
            {
                return Task.FromResult(Result<object, FailureBase>.Err(MetaDataSystemFailure.ComponentNotFound(
                    $"Payload type mismatch for {eventType}")));
            }

            return handler(_services, message, metadata, cancellationToken);
        }
    }

    protected void Register<TMessage>(string eventType, string context, MessageParser<TMessage> parser, bool idempotencyRequired = false)
        where TMessage : class, IMessage<TMessage>
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventType);
        ArgumentException.ThrowIfNullOrWhiteSpace(context);
        ArgumentNullException.ThrowIfNull(parser);

        _routes[eventType] = new EventRoute(
            eventType,
            context,
            Deserialize,
            Serialize,
            HandleAsync,
            idempotencyRequired);

        object Deserialize(ReadOnlyMemory<byte> payload)
        {
            return parser.ParseFrom(payload.Span);
        }

        ReadOnlyMemory<byte> Serialize(object value)
        {
            if (value is not IMessage message)
            {
                throw new InvalidOperationException($"Response for {eventType} must implement IMessage");
            }
            return message.ToByteArray();
        }

        async Task<Result<object, FailureBase>> HandleAsync(object value, EventMetadata metadata,
            CancellationToken cancellationToken)
        {
            if (value is not TMessage message)
            {
                return Result<object, FailureBase>.Err(MetaDataSystemFailure.ComponentNotFound(
                    $"Payload type mismatch for {eventType}"));
            }

            IEventHandler<TMessage>? handler = _services.GetService<IEventHandler<TMessage>>();
            if (handler is null)
            {
                return Result<object, FailureBase>.Err(MetaDataSystemFailure.ComponentNotFound(
                    $"No handler registered for {eventType} ({typeof(TMessage).Name})"));
            }

            return await handler.HandleAsync(message, metadata, cancellationToken);
        }
    }

    public bool TryGetRoute(string eventType, out EventRoute route)
    {
        bool found = _routes.TryGetValue(eventType, out EventRoute? resolved);
        route = resolved ?? default!;
        return found;
    }
}
