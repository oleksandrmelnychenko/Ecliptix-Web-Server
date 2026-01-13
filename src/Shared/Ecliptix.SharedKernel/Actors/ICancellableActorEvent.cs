namespace Ecliptix.SharedKernel.Actors;

public interface ICancellableActorEvent
{
    CancellationToken CancellationToken { get; }
}
