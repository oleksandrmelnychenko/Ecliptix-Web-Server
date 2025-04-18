using Akka.Actor;

namespace Ecliptix.Core.Actors;

public class EcliptixProtocolConnectionsManagerActor : ReceiveActor
{
    private readonly ILogger<EcliptixProtocolConnectionsManagerActor> _logger;
    private readonly TimeSpan? _cleanupInterval;

    public EcliptixProtocolConnectionsManagerActor(ILogger<EcliptixProtocolConnectionsManagerActor> logger,TimeSpan? cleanupInterval = null)
    {
        _logger = logger;
        _cleanupInterval = cleanupInterval;
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

    public static Props Build( ILogger<EcliptixProtocolConnectionsManagerActor> logger,TimeSpan? cleanupInterval = null)
        => Props.Create(() => new EcliptixProtocolConnectionsManagerActor(logger,cleanupInterval));
}