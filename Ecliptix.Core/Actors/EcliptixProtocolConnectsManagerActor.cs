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

    public EcliptixProtocolConnectsManagerActor(
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
        ReceiveAsync<DecryptCipherPayloadCommand>(HandleDecryptCipherPayloadCommand);
    }
    
    private async Task HandleDecryptCipherPayloadCommand(DecryptCipherPayloadCommand command)
    {
        uint connectId = command.UniqueConnectId;

        if (_connectActorRefs.TryGetValue(connectId, out IActorRef? actorRef))
        {
            byte[] result = await actorRef.Ask<byte[]>(command);
            Sender.Tell(result);
        }
    }

    private async Task
        HandleCreateConnectCommand(CreateConnectCommand command)
    {
        uint connectId = command.ConnectId;
        PubKeyExchange exchangeType = command.PubKeyExchange;

        IActorRef? actorRef =
            Context.ActorOf(
                EcliptixProtocolConnectActor.Build(),
                $"connect-{connectId}");
        
        _connectActorRefs.TryAdd(connectId, actorRef);

        ProcessAndRespondToPubKeyExchangeCommand processAndRespondToPubKeyExchangeCommand = new(connectId,exchangeType);
        ProcessAndRespondToPubKeyExchangeReply? reply =
           await  actorRef.Ask<ProcessAndRespondToPubKeyExchangeReply>(processAndRespondToPubKeyExchangeCommand);
        
        Sender.Tell(reply);
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