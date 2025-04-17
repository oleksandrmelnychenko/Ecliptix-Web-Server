using System.Collections.Concurrent;
using Akka.Actor;
using Ecliptix.Core.Protocol;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Actors;


public class EcliptixProtocolSystemActor(
    EcliptixSystemIdentityKeys localKeys,
    ILogger<EcliptixProtocolSystemActor> logger)
    : ReceiveActor
{
    private readonly ConcurrentDictionary<uint, IActorRef> _sessions = new();
    private readonly EcliptixSystemIdentityKeys _localKeys = localKeys;

    protected override void PreStart()
    {
        logger.LogInformation("MainShieldPro actor '{ActorPath}' is up and running.", Context.Self.Path);
        base.PreStart();
    }

    private static string GetManagerKey(PubKeyExchangeType type) => type.ToString();

    public static Props Props1(EcliptixSystemIdentityKeys localKeys, ILogger<EcliptixProtocolSystemActor> logger) 
        => Props.Create(() => new EcliptixProtocolSystemActor(localKeys, logger));
}