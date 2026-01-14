using Akka.Actor;
using Ecliptix.SharedKernel.Actors;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public class SecrecyHandshakeKeepAliveInterceptor(IEcliptixActorRegistry actorRegistry) : Interceptor
{
    private readonly Lazy<IActorRef> _protocolSystemActor = new(() => actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor));

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        SendKeepAlive(context);
        return await continuation(request, context);
    }

    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        SendKeepAlive(context);
        await continuation(request, responseStream, context);
    }

    public override async Task<TResponse> ClientStreamingServerHandler<TRequest, TResponse>(
        IAsyncStreamReader<TRequest> requestStream,
        ServerCallContext context,
        ClientStreamingServerMethod<TRequest, TResponse> continuation)
    {
        SendKeepAlive(context);
        return await continuation(requestStream, context);
    }

    public override async Task DuplexStreamingServerHandler<TRequest, TResponse>(
        IAsyncStreamReader<TRequest> requestStream,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        DuplexStreamingServerMethod<TRequest, TResponse> continuation)
    {
        SendKeepAlive(context);
        await continuation(requestStream, responseStream, context);
    }

    private void SendKeepAlive(ServerCallContext context)
    {
        uint connectId = (uint)context.UserState[GrpcMetadataHandler.UniqueConnectId];
        _protocolSystemActor.Value.Tell(new RouteToConnectionCommand(connectId, KeepAlive.Instance));
    }
}
