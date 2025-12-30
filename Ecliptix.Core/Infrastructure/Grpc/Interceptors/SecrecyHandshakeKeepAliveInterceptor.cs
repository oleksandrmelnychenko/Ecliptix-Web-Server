using Akka.Actor;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
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
        uint connectId = (uint)context.UserState[GrpcMetadataHandler.UniqueConnectId];

        ForwardToConnectActorEvent keepAliveForwarder = new(connectId, KeepAlive.Instance);
        _protocolSystemActor.Value.Tell(keepAliveForwarder);

        return await continuation(request, context);
    }

    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        uint connectId = (uint)context.UserState[GrpcMetadataHandler.UniqueConnectId];

        ForwardToConnectActorEvent keepAliveForwarder = new(connectId, KeepAlive.Instance);
        _protocolSystemActor.Value.Tell(keepAliveForwarder);

        await continuation(request, responseStream, context);
    }

    public override async Task<TResponse> ClientStreamingServerHandler<TRequest, TResponse>(
        IAsyncStreamReader<TRequest> requestStream,
        ServerCallContext context,
        ClientStreamingServerMethod<TRequest, TResponse> continuation)
    {
        uint connectId = (uint)context.UserState[GrpcMetadataHandler.UniqueConnectId];

        ForwardToConnectActorEvent keepAliveForwarder = new(connectId, KeepAlive.Instance);
        _protocolSystemActor.Value.Tell(keepAliveForwarder);

        return await continuation(requestStream, context);
    }

    public override async Task DuplexStreamingServerHandler<TRequest, TResponse>(
        IAsyncStreamReader<TRequest> requestStream,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        DuplexStreamingServerMethod<TRequest, TResponse> continuation)
    {
        uint connectId = (uint)context.UserState[GrpcMetadataHandler.UniqueConnectId];

        ForwardToConnectActorEvent keepAliveForwarder = new(connectId, KeepAlive.Instance);
        _protocolSystemActor.Value.Tell(keepAliveForwarder);

        await continuation(requestStream, responseStream, context);
    }
}
