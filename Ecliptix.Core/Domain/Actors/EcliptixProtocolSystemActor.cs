using Akka.Actor;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Utilities;
using Serilog;

namespace Ecliptix.Core.Domain.Actors;

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
            Log.Warning(ActorConstants.LogMessages.SupervisedActorTerminated, t.ActorRef.Path);
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
        string actorName = $"{ActorConstants.ActorNamePrefixes.Connect}{connectId}";
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
        string actorName = $"{ActorConstants.ActorNamePrefixes.Connect}{connectId}";
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
                    EcliptixProtocolFailure.ActorNotCreated($"{ActorConstants.ErrorMessages.FailedToCreateActor}{connectId}", ex));
            }
        }

        return Result<IActorRef, EcliptixProtocolFailure>.Ok(connectActor);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return new OneForOneStrategy(
            maxNrOfRetries: ActorConstants.Supervision.MaxRetries,
            withinTimeRange: TimeSpan.FromMinutes(ActorConstants.Supervision.TimeoutMinutes),
            decider: Decider.From(ChildFailureDecider));
    }

    private static Directive ChildFailureDecider(Exception ex)
    {
        switch (ex)
        {
            case ActorInitializationException initEx:
                Log.Error(initEx, ActorConstants.LogMessages.InitializationFailed);
                return Directive.Stop;

            case TimeoutException timeoutEx:
                Log.Warning(timeoutEx, ActorConstants.LogMessages.TimeoutEncountered);
                return Directive.Restart;

            case UnauthorizedAccessException unauthorizedEx:
                Log.Error(unauthorizedEx, ActorConstants.LogMessages.AuthorizationFailure);
                return Directive.Stop;

            case ArgumentException argEx:
                Log.Error(argEx, ActorConstants.LogMessages.InvalidArguments);
                return Directive.Stop;

            case InvalidOperationException invalidOpEx when invalidOpEx.Message.Contains(ActorConstants.ErrorMessages.Cryptographic):
                Log.Error(invalidOpEx, ActorConstants.LogMessages.CryptographicError);
                return Directive.Restart;

            case InvalidOperationException invalidOpEx:
                Log.Warning(invalidOpEx, ActorConstants.LogMessages.InvalidOperation);
                return Directive.Restart;

            case IOException ioEx:
                Log.Warning(ioEx, ActorConstants.LogMessages.IoError);
                return Directive.Restart;

            case System.Net.NetworkInformation.NetworkInformationException netEx:
                Log.Warning(netEx, ActorConstants.LogMessages.NetworkError);
                return Directive.Restart;

            case OutOfMemoryException memEx:
                Log.Error(memEx, ActorConstants.LogMessages.OutOfMemory);
                return Directive.Escalate;

            case StackOverflowException stackEx:
                Log.Error(stackEx, ActorConstants.LogMessages.StackOverflow);
                return Directive.Escalate;

            default:
                Log.Error(ex, ActorConstants.LogMessages.UnhandledException, ex.GetType().Name);
                return Directive.Stop;
        }
    }

    public static Props Build()
    {
        return Props.Create(() => new EcliptixProtocolSystemActor());
    }
}