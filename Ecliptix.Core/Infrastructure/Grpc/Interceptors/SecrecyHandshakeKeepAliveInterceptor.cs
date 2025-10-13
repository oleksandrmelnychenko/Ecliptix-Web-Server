using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Core.Domain.Events;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public class SessionKeepAliveInterceptor(IEcliptixActorRegistry actorRegistry) : Interceptor
{
    private readonly Lazy<IActorRef> _protocolSystemActor = new(() => actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor));

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