using Akka.Actor;

namespace Ecliptix.Core.Services.Utilities.CipherPayloadHandler;

public class CipherPayloadHandlerFactory : ICipherPayloadHandlerFactory
{
    private readonly IEcliptixActorRegistry actorRegistry;
    
    public CipherPayloadHandlerFactory(IEcliptixActorRegistry actorRegistry)
    {
        this.actorRegistry = actorRegistry;
    }

    public ICipherPayloadHandler Create<T>() where T : ActorBase
    {
        return new CipherPayloadHandler<T>(actorRegistry);
    }
}