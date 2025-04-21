using System.Collections.Concurrent;
using Akka.Actor;
using Ecliptix.Core.Actors.Messages;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Actors;
public record CreateConnectCommand(uint ConnectId, PubKeyExchange PubKeyExchange);

    public class EcliptixProtocolConnectsManagerActor : ReceiveActor
    {
        private readonly ILogger<EcliptixProtocolConnectsManagerActor> _logger;
        private readonly TimeSpan _connectTimeout = TimeSpan.FromSeconds(10); 
        private readonly TimeSpan? _cleanupInterval; // Keep if used elsewhere

        private readonly ConcurrentDictionary<uint, IActorRef> _activeConnections = new();
        private readonly Dictionary<uint, PendingConnectRequest> _pendingConnections = new();

        private EcliptixProtocolConnectsManagerActor(
            ILogger<EcliptixProtocolConnectsManagerActor> logger,
            TimeSpan? cleanupInterval = null)
        {
            _logger = logger;
            _cleanupInterval = cleanupInterval;
            Become(Ready);
        }

        private void Ready()
        {
            Receive<CreateConnectCommand>(HandleCreateConnectCommand);
            Receive<ConnectInitializationSuccess>(HandleConnectSuccess);
            Receive<ConnectInitializationFailure>(HandleConnectFailure);
            Receive<ConnectInitializationTimeout>(HandleConnectTimeout);
            Receive<Terminated>(HandleTerminated);
        }

        private void HandleCreateConnectCommand(CreateConnectCommand command)
        {
            uint connectId = command.ConnectId;
            IActorRef originalSender = Sender;

            if (_activeConnections.ContainsKey(connectId) || _pendingConnections.ContainsKey(connectId))
            {
                _logger.LogWarning("Connect request for existing/pending ID {ConnectId}", connectId);
                originalSender.Tell(new Status.Failure(new InvalidOperationException($"ConnectId {connectId} already exists or is pending.")));
                return;
            }

            try
            {
                IActorRef connectActorRef = Context.ActorOf(
                    EcliptixProtocolConnectActor.Build(),
                    $"connect-{connectId}");

                ICancelable? cancellable = Context.System.Scheduler.ScheduleTellOnceCancelable(
                    _connectTimeout,
                    Self,
                    new ConnectInitializationTimeout(connectId, connectActorRef), // Pass ref
                    Self);

                _pendingConnections.Add(connectId, new PendingConnectRequest(originalSender, cancellable));

                _logger.LogInformation("Initiating connection for {ConnectId}", connectId);
                connectActorRef.Tell(new RespondToPubKeyExchangeCommand(connectId, command.PubKeyExchange));

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create connect actor for {ConnectId}", connectId);
                originalSender.Tell(new Status.Failure(ex));
            }
        }

        private void HandleConnectSuccess(ConnectInitializationSuccess success)
        {
            uint connectId = success.ConnectId;

            if (_pendingConnections.TryGetValue(connectId, out var pendingRequest))
            {
                pendingRequest.TimeoutSchedule.Cancel();
                _pendingConnections.Remove(connectId);

                if (_activeConnections.TryAdd(connectId, success.ConnectActorRef))
                {
                    _logger.LogInformation("Connection {ConnectId} successfully established. Watching actor.", connectId);
                    Context.Watch(success.ConnectActorRef);
                    pendingRequest.OriginalSender.Tell(success.PubKeyExchangeResponse);
                }
                else
                {
                    _logger.LogWarning("Failed to add established connection {ConnectId} (race?). Stopping orphan.", connectId);
                    pendingRequest.OriginalSender.Tell(new Status.Failure(new InvalidOperationException($"Internal error adding connection {connectId}.")));
                    Context.Stop(success.ConnectActorRef);
                }
            }
            else
            {
                _logger.LogWarning("Received success for unknown/timed-out connection {ConnectId}. Stopping actor.", connectId);
                Context.Stop(success.ConnectActorRef); 
            }
        }

        private void HandleConnectFailure(ConnectInitializationFailure failure)
        {
            uint connectId = failure.ConnectId;

            if (_pendingConnections.TryGetValue(connectId, out PendingConnectRequest? pendingRequest))
            {
                pendingRequest.TimeoutSchedule.Cancel(); 
                _pendingConnections.Remove(connectId);

                _logger.LogError(failure.FailureReason, "Connection {ConnectId} failed initialization.", connectId);
                pendingRequest.OriginalSender.Tell(new Status.Failure(failure.FailureReason)); 

                Context.Stop(failure.ConnectActorRef);
            }
            else
            {
                _logger.LogWarning("Received failure for unknown/timed-out connection {ConnectId}.", connectId);
                 Context.Stop(failure.ConnectActorRef);
            }
        }

        private void HandleConnectTimeout(ConnectInitializationTimeout timeout)
        {
            uint connectId = timeout.ConnectId;

            if (_pendingConnections.Remove(connectId, out PendingConnectRequest? pendingRequest))
            {
                _logger.LogWarning("Connection {ConnectId} timed out during initialization.", connectId);
                TimeoutException timeoutException = new($"Initialization for connectId {connectId} timed out after {_connectTimeout}.");
                pendingRequest.OriginalSender.Tell(new Status.Failure(timeoutException)); 

                _logger.LogInformation("Stopping timed-out actor for {ConnectId}", connectId);
                Context.Stop(timeout.ConnectActorRef);
            }
            else
            {
                _logger.LogInformation("Received timeout for already handled connection {ConnectId}.", connectId);
            }
        }

        private void HandleTerminated(Terminated terminated)
        {
            IActorRef stoppedActorRef = terminated.ActorRef;
            _logger.LogDebug("Received Terminated message for {ActorPath}", stoppedActorRef.Path);

            // Find the connectId associated with the terminated actor
            uint? connectIdToRemove = null;
            // This iteration can be slow for *very* large numbers of connections.
            // Consider a reverse dictionary (IActorRef -> uint) if this becomes a bottleneck.
            foreach (var kvp in _activeConnections)
            {
                if (kvp.Value.Equals(stoppedActorRef))
                {
                    connectIdToRemove = kvp.Key;
                    break;
                }
            }

            if (connectIdToRemove.HasValue)
            {
                // Remove the stale entry from the dictionary
                if (_activeConnections.TryRemove(connectIdToRemove.Value, out _))
                {
                    _logger.LogInformation("Connection actor for {ConnectId} terminated. Removed from active connections.", connectIdToRemove.Value);
                    // Optionally: Notify other system parts that this connection is gone
                }
                else
                {
                    _logger.LogWarning("Tried removing terminated actor {ConnectId}, but it was already gone.", connectIdToRemove.Value);
                }
            }
            else
            {
                // This could happen if an actor we weren't tracking terminates (e.g., timed out before success)
                _logger.LogWarning("Received Terminated for actor {ActorPath} not found in active connections.", stoppedActorRef.Path);
            }
            // No need to call Context.Unwatch() explicitly
        }

        protected override void PostStop()
        {
            _logger.LogInformation("Manager actor stopping.");
            // Child actors are stopped automatically by Akka when the parent stops.
            base.PostStop();
        }

        protected override void PreStart()
        {
            _logger.LogInformation("Manager actor '{ActorPath}' starting.", Context.Self.Path);
            base.PreStart();
        }

        public static Props Build(ILogger<EcliptixProtocolConnectsManagerActor> logger, TimeSpan? cleanupInterval = null)
            => Props.Create(() => new EcliptixProtocolConnectsManagerActor(logger, cleanupInterval));
    }
