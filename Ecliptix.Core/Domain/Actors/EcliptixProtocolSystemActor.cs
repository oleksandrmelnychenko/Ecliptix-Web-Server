using Akka.Actor;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Protocol;
using Serilog;

namespace Ecliptix.Core.Domain.Actors;

public record BeginAppDeviceEphemeralConnectActorEvent(PubKeyExchange PubKeyExchange, uint UniqueConnectId);

public record DecryptCipherPayloadActorEvent(
    PubKeyExchangeType PubKeyExchangeType,
    CipherPayload CipherPayload);

public record EncryptPayloadActorEvent(
    PubKeyExchangeType PubKeyExchangeType,
    byte[] Payload);

public record ClientDisconnectedActorEvent(uint ConnectId);

public record ForwardToConnectActorEvent(uint ConnectId, object Payload);

public record RestoreAppDeviceSecrecyChannelState;

public class EcliptixProtocolSystemActor : ReceiveActor
{
    public EcliptixProtocolSystemActor()
    {
        Become(Ready);
    }

    private void Ready()
    {
        ReceiveAsync<BeginAppDeviceEphemeralConnectActorEvent>(ProcessNewSessionRequest);
        ReceiveAsync<ForwardToConnectActorEvent>(ProcessForwarding);
        Receive<Terminated>(t =>
        {
            Log.Warning("Supervised session actor {ActorPath} has terminated. Its resources are released",
                t.ActorRef.Path);
        });

        Receive<ClientDisconnectedActorEvent>(cmd =>
        {
            string actorName = $"connect-{cmd.ConnectId}";
            IActorRef connectActor = Context.Child(actorName);
            if (!connectActor.IsNobody())
            {
                connectActor.Forward(cmd);
            }
        });
    }

    private async Task ProcessNewSessionRequest(BeginAppDeviceEphemeralConnectActorEvent actorEvent)
    {
        uint connectId = actorEvent.UniqueConnectId;
        Result<IActorRef, EcliptixProtocolFailure> connectActorResult = GetOrCreateConnectActor(connectId);
        
        if (connectActorResult.IsErr)
        {
            Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(connectActorResult.UnwrapErr()));
            return;
        }

        IActorRef connectActor = connectActorResult.Unwrap();
        DeriveSharedSecretActorEvent deriveSharedSecretEvent = new(connectId, actorEvent.PubKeyExchange);
        Result<DeriveSharedSecretReply, EcliptixProtocolFailure> result =
            await connectActor.Ask<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(deriveSharedSecretEvent);

        Sender.Tell(result);
    }

    private async Task ProcessForwarding(ForwardToConnectActorEvent message)
    {
        uint connectId = message.ConnectId;
        string actorName = $"connect-{connectId}";
        IActorRef connectActor = Context.Child(actorName);

        if (connectActor.IsNobody() && message.Payload is not KeepAlive)
        {
            Result<IActorRef, EcliptixProtocolFailure> connectActorResult = GetOrCreateConnectActor(connectId);
            if (connectActorResult.IsErr)
            {
                Sender.Tell(Result<object, EcliptixProtocolFailure>.Err(connectActorResult.UnwrapErr()));
                return;
            }
            connectActor = connectActorResult.Unwrap();
        }

        if (message.Payload is KeepAlive)
        {
            connectActor.Tell(message.Payload, ActorRefs.NoSender);
        }
        else
        {
            object? result = await connectActor.Ask(message.Payload);
            Sender.Tell(result);
        }
    }

    private Result<IActorRef, EcliptixProtocolFailure> GetOrCreateConnectActor(uint connectId)
    {
        string actorName = $"connect-{connectId}";
        IActorRef connectActor = Context.Child(actorName);

        if (connectActor.IsNobody())
        {
            try
            {
                connectActor = Context.ActorOf(EcliptixProtocolConnectActor.Build(connectId), actorName);
                Context.Watch(connectActor);
                return Result<IActorRef, EcliptixProtocolFailure>.Ok(connectActor);
            }
            catch (Exception ex)
            {
                return Result<IActorRef, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.ActorNotCreated($"Failed to create actor for connectId: {connectId}", ex));
            }
        }

        return Result<IActorRef, EcliptixProtocolFailure>.Ok(connectActor);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return new OneForOneStrategy(
            maxNrOfRetries: 3,
            withinTimeRange: TimeSpan.FromMinutes(5),
            decider: Decider.From(ChildFailureDecider));
    }

    private static Directive ChildFailureDecider(Exception ex)
    {
        switch (ex)
        {
            case ActorInitializationException initEx:
                Log.Error(initEx, "Protocol connect actor failed during initialization. Stopping to prevent further issues");
                return Directive.Stop;

            case TimeoutException timeoutEx:
                Log.Warning(timeoutEx, "Protocol connect actor encountered timeout. Restarting");
                return Directive.Restart;

            case UnauthorizedAccessException unauthorizedEx:
                Log.Error(unauthorizedEx, "Protocol connect actor encountered authorization failure. Stopping");
                return Directive.Stop;

            case ArgumentException argEx:
                Log.Error(argEx, "Protocol connect actor failed with invalid arguments. Stopping to prevent repeated failures");
                return Directive.Stop;

            case InvalidOperationException invalidOpEx when invalidOpEx.Message.Contains("cryptographic"):
                Log.Error(invalidOpEx, "Protocol connect actor encountered cryptographic error. Restarting");
                return Directive.Restart;

            case InvalidOperationException invalidOpEx:
                Log.Warning(invalidOpEx, "Protocol connect actor encountered invalid operation. Restarting");
                return Directive.Restart;

            case IOException ioEx:
                Log.Warning(ioEx, "Protocol connect actor encountered IO error. Restarting");
                return Directive.Restart;

            case System.Net.NetworkInformation.NetworkInformationException netEx:
                Log.Warning(netEx, "Protocol connect actor encountered network error. Restarting");
                return Directive.Restart;

            case OutOfMemoryException memEx:
                Log.Error(memEx, "Protocol connect actor out of memory. Escalating to parent");
                return Directive.Escalate;

            case StackOverflowException stackEx:
                Log.Error(stackEx, "Protocol connect actor stack overflow. Escalating to parent");
                return Directive.Escalate;

            default:
                Log.Error(ex, "Protocol connect actor encountered unhandled exception of type {ExceptionType}. Stopping to prevent cascading failures", ex.GetType().Name);
                return Directive.Stop;
        }
    }

    public static Props Build()
    {
        // AOT-compatible lambda - no closures captured
        return Props.Create(() => new EcliptixProtocolSystemActor());
    }
}