using Akka.Actor;

namespace Ecliptix.Core.Actors.Messages;

/// <summary>
/// Message sent from a child connection actor to the manager
/// indicating that the initialization process failed.
/// </summary>
public record ConnectInitializationFailure
{
    /// <summary>
    /// The unique identifier for the connection attempt that failed.
    /// </summary>
    public uint ConnectId { get; }

    /// <summary>
    /// The reason why the initialization failed. Could be a standard
    /// Exception or a more specific custom exception/error type.
    /// </summary>
    public Exception FailureReason { get; }

    /// <summary>
    /// A reference to the child actor instance that encountered the failure.
    /// The manager might use this to explicitly stop the actor.
    /// </summary>
    public IActorRef ConnectActorRef { get; }

    /// <summary>
    /// Constructor for ConnectInitializationFailure.
    /// </summary>
    /// <param name="connectId">The ID of the failed connection.</param>
    /// <param name="failureReason">The exception indicating the failure cause.</param>
    /// <param name="connectActorRef">The reference to the actor that failed.</param>
    public ConnectInitializationFailure(uint connectId, Exception failureReason, IActorRef connectActorRef)
    {
        ConnectId = connectId; 
        FailureReason = failureReason ?? throw new ArgumentNullException(nameof(failureReason));
        ConnectActorRef = connectActorRef ?? throw new ArgumentNullException(nameof(connectActorRef));
    }
}