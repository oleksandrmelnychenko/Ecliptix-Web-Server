namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents;

public interface ICancellableActorEvent
{
    CancellationToken CancellationToken { get; }
}

public record PrepareForTerminationMessage;
