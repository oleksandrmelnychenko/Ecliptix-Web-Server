using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Domain.Actors;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public class SessionKeepAliveInterceptor : Interceptor
{
    // Use a Lazy<T> to resolve the actor reference only once, the first time it's needed.
    // This is thread-safe and efficient.
    private readonly Lazy<IActorRef> _protocolSystemActor;

    // Inject the registry, which IS available in the DI container.
    public SessionKeepAliveInterceptor(IEcliptixActorRegistry actorRegistry)
    {
        _protocolSystemActor = new Lazy<IActorRef>(() => actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor));
    }
    
    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        uint connectId = (uint)context.UserState[GrpcMetadataHandler.UniqueConnectId];
        ForwardToConnectActorEvent keepAliveForwarder = new(connectId, KeepAlive.Instance);
        _protocolSystemActor.Value.Tell(keepAliveForwarder);

        return await continuation(request, context);
    }
}