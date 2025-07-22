using Akka.Actor;

namespace Ecliptix.Core.Services.Utilities.CipherPayloadHandler;

public interface ICipherPayloadHandlerFactory
{
    ICipherPayloadHandler Create<T>() where T : ActorBase;
}