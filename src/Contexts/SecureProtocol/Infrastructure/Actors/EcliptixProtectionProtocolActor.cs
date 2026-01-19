using Akka.Actor;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;

namespace Ecliptix.SecureProtocol.Infrastructure.Actors;

public sealed class EcliptixProtectionProtocolActor : ReceiveActor
{
    public EcliptixProtectionProtocolActor()
    {
        Become(Ready);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return new OneForOneStrategy(
            maxNrOfRetries: ActorConstants.Supervision.MaxRetries,
            withinTimeRange: TimeSpan.FromMinutes(ActorConstants.Supervision.TimeoutMinutes),
            decider: Decider.From(ChildFailureDecider));
    }

    private void Ready()
    {
        ReceiveAsync<InitiateEphemeralConnectCommand>(ProcessNewSessionRequest);
        ReceiveAsync<RouteToConnectionCommand>(ProcessForwarding);
        Receive<Terminated>(_ => { });
    }

    private async Task ProcessNewSessionRequest(InitiateEphemeralConnectCommand actorEvent)
    {
        uint connectId = actorEvent.UniqueConnectId;
        Result<IActorRef, EcliptixProtocolFailure> connectActorResult = GetOrCreateConnectActor(connectId);

        if (connectActorResult.IsErr)
        {
            Sender.Tell(Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>.Err(connectActorResult.UnwrapErr()));
            return;
        }

        IActorRef connectActor = connectActorResult.Unwrap();
        DeriveSharedSecretCommand deriveSharedSecretEvent =
            new(connectId, actorEvent.ExchangeType, actorEvent.HandshakeInit);
        Result<DeriveSharedSecretResponse, EcliptixProtocolFailure> result =
            await connectActor.Ask<Result<DeriveSharedSecretResponse, EcliptixProtocolFailure>>(deriveSharedSecretEvent);

        Sender.Tell(result);
    }

    private async Task ProcessForwarding(RouteToConnectionCommand message)
    {
        uint connectId = message.ConnectId;
        string actorName = GetConnectActorName(connectId);
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

    private static Result<IActorRef, EcliptixProtocolFailure> GetOrCreateConnectActor(uint connectId)
    {
        string actorName = GetConnectActorName(connectId);
        IActorRef connectActor = Context.Child(actorName);

        if (!connectActor.IsNobody())
        {
            return Result<IActorRef, EcliptixProtocolFailure>.Ok(connectActor);
        }

        try
        {
            connectActor = Context.ActorOf(EcliptixProtocolConnectActor.Build(connectId), actorName);
            Context.Watch(connectActor);
            return Result<IActorRef, EcliptixProtocolFailure>.Ok(connectActor);
        }
        catch (Exception ex)
        {
            return Result<IActorRef, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ActorNotCreated(
                    $"{ActorConstants.ErrorMessages.FailedToCreateActor}{connectId}", ex));
        }
    }

    private static string GetConnectActorName(uint connectId) =>
        $"{ActorConstants.ActorNamePrefixes.Connect}{connectId}";

    private static Directive ChildFailureDecider(Exception ex)
    {
        return ex switch
        {
            ActorInitializationException => Directive.Stop,
            TimeoutException => Directive.Restart,
            UnauthorizedAccessException => Directive.Stop,
            ArgumentException => Directive.Stop,
            InvalidOperationException invalidOpEx when invalidOpEx.Message.Contains(ActorConstants.ErrorMessages
                .Cryptographic) => Directive.Restart,
            InvalidOperationException => Directive.Restart,
            IOException => Directive.Restart,
            System.Net.NetworkInformation.NetworkInformationException => Directive.Restart,
            OutOfMemoryException => Directive.Escalate,
            StackOverflowException => Directive.Escalate,
            _ => Directive.Stop
        };
    }

    public static Props Build()
    {
        return Props.Create(() => new EcliptixProtectionProtocolActor());
    }
}
