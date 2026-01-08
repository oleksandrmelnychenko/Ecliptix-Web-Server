using Ecliptix.Protobuf.Transport.Common;
using Ecliptix.SharedKernel;
using Google.Protobuf;
using Microsoft.Extensions.DependencyInjection;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

public abstract class ProtobufEventRouteProvider(IServiceProvider services) : IEventRouteProvider
{
    private readonly Dictionary<TransportEventType, EventRoute> _routes = new();

    protected void Register<TMessage>(TransportEventType eventType, EventContext context, MessageParser<TMessage> parser,
        Func<IServiceProvider, TMessage, EventMetadata, CancellationToken, Task<Result<object, FailureBase>>> handler,
        bool idempotencyRequired = false)
        where TMessage : class, IMessage<TMessage>
    {
        if (eventType == TransportEventType.Unspecified)
        {
            throw new ArgumentException("eventType is required", nameof(eventType));
        }
        if (context == EventContext.Unspecified)
        {
            throw new ArgumentException("context is required", nameof(context));
        }
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

            return handler(services, message, metadata, cancellationToken);
        }
    }

    protected void Register<TMessage>(TransportEventType eventType, EventContext context, MessageParser<TMessage> parser, bool idempotencyRequired = false)
        where TMessage : class, IMessage<TMessage>
    {
        if (eventType == TransportEventType.Unspecified)
        {
            throw new ArgumentException("eventType is required", nameof(eventType));
        }
        if (context == EventContext.Unspecified)
        {
            throw new ArgumentException("context is required", nameof(context));
        }
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

            IEventHandler<TMessage>? handler = services.GetService<IEventHandler<TMessage>>();
            if (handler is null)
            {
                return Result<object, FailureBase>.Err(MetaDataSystemFailure.ComponentNotFound(
                    $"No handler registered for {eventType} ({typeof(TMessage).Name})"));
            }

            return await handler.HandleAsync(message, metadata, cancellationToken);
        }
    }

    public bool TryGetRoute(TransportEventType eventType, out EventRoute route)
    {
        bool found = _routes.TryGetValue(eventType, out EventRoute? resolved);
        route = resolved ?? default!;
        return found;
    }
}
