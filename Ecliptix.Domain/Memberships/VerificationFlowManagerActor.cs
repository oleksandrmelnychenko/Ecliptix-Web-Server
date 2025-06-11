using Akka.Actor;
using Ecliptix.Domain.Memberships.Events;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Extensions.Localization;
using Serilog;

namespace Ecliptix.Domain.Memberships;

public record ClientDisconnectedEvent;

public class VerificationFlowManagerActor : ReceiveActor
{
    private readonly IStringLocalizer<VerificationFlowManagerActor> _localizer;
    private readonly IActorRef _persistor;
    private readonly IActorRef _membershipActor;
    private readonly SNSProvider _snsProvider;

    public VerificationFlowManagerActor(
        IActorRef persistor,
        IActorRef membershipActor,
        SNSProvider snsProvider,
        IStringLocalizer<VerificationFlowManagerActor> localizer)
    {
        _localizer = localizer;
        _persistor = persistor;
        _membershipActor = membershipActor;
        _snsProvider = snsProvider;

        Become(Ready);
    }

    private void Ready()
    {
        Receive<InitiateVerificationFlowActorEvent>(HandleInitiateFlow);
        Receive<VerifyFlowActorEvent>(HandleVerifyFlow);
        Receive<Terminated>(HandleTerminated);

        Receive<EnsurePhoneNumberActorEvent>(cmd => _persistor.Forward(cmd));
    }

    private void HandleInitiateFlow(InitiateVerificationFlowActorEvent @event)
    {
        string actorName = GetActorName(@event.ConnectId);
        IActorRef? childActor = Context.Child(actorName);

        if (!childActor.IsNobody())
        {
            childActor.Forward(@event);
        }
        else
        {
            if (@event.RequestType == InitiateVerificationRequest.Types.Type.SendOtp)
            {
                IActorRef? newFlowActor = Context.ActorOf(VerificationFlowActor.Build(
                    @event.ConnectId,
                    @event.PhoneNumberIdentifier,
                    @event.AppDeviceIdentifier,
                    @event.Purpose,
                    @event.ChannelWriter,
                    _persistor,
                    _membershipActor,
                    _snsProvider,
                    _localizer
                ), actorName);

                Context.Watch(newFlowActor);
                Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
            }
            else
            {
                Sender.Tell(Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("No active session found for resend request.")));
                @event.ChannelWriter.TryComplete();
            }
        }
    }

    private void HandleVerifyFlow(VerifyFlowActorEvent actorEvent)
    {
        IActorRef? childActor = Context.Child(GetActorName(actorEvent.ConnectId));

        if (!childActor.IsNobody())
        {
            childActor.Forward(actorEvent);
        }
        else
        {
            Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.NotFound("No active verification flow found for this connection.")));
        }
    }

    private void HandleTerminated(Terminated msg)
    {
        Log.Information("Verification flow actor {ActorPath} has terminated.", msg.ActorRef.Path);
    }

    private static string GetActorName(uint connectId) => $"flow-{connectId}";

    public static Props Build(IActorRef persistor, IActorRef membershipActor, SNSProvider snsProvider,
        IStringLocalizer<VerificationFlowManagerActor> localizer) =>
        Props.Create(() => new VerificationFlowManagerActor(persistor, membershipActor, snsProvider, localizer));
}