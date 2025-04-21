using Akka.Actor;

namespace Ecliptix.Core.Actors.Messages;

/// <summary>
/// Internal record used by EcliptixProtocolConnectsManagerActor
/// to track connection requests that are awaiting a response
/// from their corresponding child connection actor.
/// </summary>
internal record PendingConnectRequest
{
    /// <summary>
    /// The actor who originally sent the CreateConnectCommand and
    /// should receive the final result (success or failure).
    /// </summary>
    public IActorRef OriginalSender { get; }

    /// <summary>
    /// The cancellation token for the scheduled timeout message.
    /// This should be cancelled if the child actor responds
    /// before the timeout duration expires.
    /// </summary>
    public ICancelable TimeoutSchedule { get; }

    /// <summary>
    /// Constructor for PendingConnectRequest.
    /// </summary>
    /// <param name="originalSender">The original requester actor.</param>
    /// <param name="timeoutSchedule">The cancellable timeout schedule.</param>
    public PendingConnectRequest(IActorRef originalSender, ICancelable timeoutSchedule)
    {
        OriginalSender = originalSender ?? throw new ArgumentNullException(nameof(originalSender));
        TimeoutSchedule = timeoutSchedule ?? throw new ArgumentNullException(nameof(timeoutSchedule));
    }
}