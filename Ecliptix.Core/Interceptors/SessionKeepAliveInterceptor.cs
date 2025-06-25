using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Ecliptix.Core.Services.Utilities;

namespace Ecliptix.Core.Interceptors;

public class SessionKeepAliveInterceptor : Interceptor
{
    // Use a Lazy<T> to resolve the actor reference only once, the first time it's needed.
    // This is thread-safe and efficient.
    private readonly Lazy<IActorRef> _protocolSystemActor;

    // Inject the registry, which IS available in the DI container.
    public SessionKeepAliveInterceptor(IActorRegistry actorRegistry)
    {
        _protocolSystemActor = new Lazy<IActorRef>(() => 
            actorRegistry.Get<EcliptixProtocolSystemActor>());
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