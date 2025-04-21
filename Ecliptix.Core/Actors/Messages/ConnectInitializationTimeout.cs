using Akka.Actor;

namespace Ecliptix.Core.Actors.Messages;

/// <summary>
/// Internal message used by EcliptixProtocolConnectsManagerActor
/// to signal that a connection initialization request has timed out.
/// This message is typically scheduled and sent to Self.
/// </summary>
internal record ConnectInitializationTimeout // Often marked internal as it's a manager detail
{
    /// <summary>
    /// The unique identifier for the connection attempt that timed out.
    /// </summary>
    public uint ConnectId { get; }

    /// <summary>
    /// A reference to the child actor instance that was expected to respond.
    /// The manager needs this reference to stop the potentially unresponsive actor.
    /// </summary>
    public IActorRef ConnectActorRef { get; }

    /// <summary>
    /// Constructor for ConnectInitializationTimeout.
    /// </summary>
    /// <param name="connectId">The ID of the timed-out connection.</param>
    /// <param name="connectActorRef">The reference to the actor that timed out.</param>
    public ConnectInitializationTimeout(uint connectId, IActorRef connectActorRef)
    {
        ConnectId = connectId;
        ConnectActorRef = connectActorRef ?? throw new ArgumentNullException(nameof(connectActorRef));
    }
}