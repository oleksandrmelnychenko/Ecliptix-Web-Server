using System.Collections.Concurrent;
using Akka.Actor;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Actors;

public record CreateConnectCommand(uint ConnectId, PubKeyExchange PubKeyExchange);

public class EcliptixProtocolConnectsManagerActor : ReceiveActor
{
    private readonly ILogger<EcliptixProtocolConnectsManagerActor> _logger;
    private readonly TimeSpan? _cleanupInterval;

    private readonly ConcurrentDictionary<uint, IActorRef> _connectActorRefs = new();

    private EcliptixProtocolConnectsManagerActor(
        ILogger<EcliptixProtocolConnectsManagerActor> logger,
        TimeSpan? cleanupInterval = null)
    {
        _logger = logger;
        _cleanupInterval = cleanupInterval;
        Become(Ready);
    }

    private void Ready()
    {
        ReceiveAsync<CreateConnectCommand>(HandleCreateConnectCommand);
    }

    private async Task
        HandleCreateConnectCommand(CreateConnectCommand command)
    {
        uint connectId = command.ConnectId;
        PubKeyExchange exchangeType = command.PubKeyExchange;
        
        IActorRef? actorRef =
            Context.ActorOf(
                EcliptixProtocolConnectActor.Build(connectId, exchangeType),
                $"connect-{connectId}");

        _connectActorRefs.TryAdd(connectId, actorRef);
    }

    protected override void PostStop()
    {
        base.PostStop();
    }

    protected override void PreStart()
    {
        _logger.LogInformation("MainShieldPro actor '{ActorPath}' is up and running.", Context.Self.Path);
        base.PreStart();
    }

    public static Props Build(ILogger<EcliptixProtocolConnectsManagerActor> logger, TimeSpan? cleanupInterval = null)
        => Props.Create(() => new EcliptixProtocolConnectsManagerActor(logger, cleanupInterval));
}