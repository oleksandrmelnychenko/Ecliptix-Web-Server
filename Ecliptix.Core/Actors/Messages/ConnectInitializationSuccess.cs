using Akka.Actor;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Actors.Messages;

/// <summary>
/// Message sent from a child connection actor to the manager
/// indicating that the initialization process and initial key exchange
/// were completed successfully.
/// </summary>
public record ConnectInitializationSuccess
{
    /// <summary>
    /// The unique identifier for the connection that succeeded.
    /// </summary>
    public uint ConnectId { get; }

    /// <summary>
    /// The PubKeyExchange message payload that the manager should
    /// forward to the original requester. This typically contains
    /// the initiating actor's public keys and initial DH key needed
    /// by the peer.
    /// </summary>
    public PubKeyExchange PubKeyExchangeResponse { get; }

    /// <summary>
    /// A reference to the child actor instance that successfully initialized.
    /// The manager will store this reference and start watching the actor.
    /// </summary>
    public IActorRef ConnectActorRef { get; }

    /// <summary>
    /// Constructor for ConnectInitializationSuccess.
    /// </summary>
    /// <param name="connectId">The ID of the successful connection.</param>
    /// <param name="pubKeyExchangeResponse">The response payload to be forwarded.</param>
    /// <param name="connectActorRef">The reference to the successfully initialized actor.</param>
    public ConnectInitializationSuccess(uint connectId, PubKeyExchange pubKeyExchangeResponse, IActorRef connectActorRef)
    {
        ConnectId = connectId; // uint is non-nullable
        PubKeyExchangeResponse = pubKeyExchangeResponse ?? throw new ArgumentNullException(nameof(pubKeyExchangeResponse));
        ConnectActorRef = connectActorRef ?? throw new ArgumentNullException(nameof(connectActorRef));
    }
}