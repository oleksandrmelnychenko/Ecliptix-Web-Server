using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Serilog;

namespace Ecliptix.Domain.Memberships.WorkerActors;

public class VerificationFlowManagerActor : ReceiveActor
{
    private readonly ILocalizationProvider _localizationProvider;
    private readonly IActorRef _membershipActor;
    private readonly IActorRef _persistor;
    private readonly SNSProvider _snsProvider;

    public VerificationFlowManagerActor(
        IActorRef persistor,
        IActorRef membershipActor,
        SNSProvider snsProvider,
        ILocalizationProvider localizationProvider)
    {
        _persistor = persistor;
        _membershipActor = membershipActor;
        _snsProvider = snsProvider;
        _localizationProvider = localizationProvider;

        Become(Ready);
    }

    private void Ready()
    {
        Receive<InitiateVerificationFlowActorEvent>(HandleInitiateFlow);
        Receive<VerifyFlowActorEvent>(HandleVerifyFlow);
        Receive<Terminated>(HandleTerminated);
        Receive<EnsurePhoneNumberActorEvent>(actorEvent => _persistor.Forward(actorEvent));
    }

    private void HandleInitiateFlow(InitiateVerificationFlowActorEvent actorEvent)
    {
        string actorName = GetActorName(actorEvent.ConnectId);
        IActorRef? childActor = Context.Child(actorName);

        if (!childActor.IsNobody())
        {
            childActor.Forward(actorEvent);
        }
        else
        {
            if (actorEvent.RequestType == InitiateVerificationRequest.Types.Type.SendOtp)
            {
                IActorRef? newFlowActor = Context.ActorOf(VerificationFlowActor.Build(
                    actorEvent.ConnectId,
                    actorEvent.PhoneNumberIdentifier,
                    actorEvent.AppDeviceIdentifier,
                    actorEvent.Purpose,
                    actorEvent.ChannelWriter,
                    _persistor,
                    _membershipActor,
                    _snsProvider,
                    _localizationProvider,
                    actorEvent.CultureName
                ), actorName);

                Context.Watch(newFlowActor);
                Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
            }
            else
            {
                string message = _localizationProvider.Localize(VerificationFlowMessageKeys.VerificationFlowNotFound,
                    actorEvent.CultureName);
                Sender.Tell(Result<Unit, VerificationFlowFailure>.Err(VerificationFlowFailure.NotFound(message)));
                actorEvent.ChannelWriter.TryComplete();
            }
        }
    }

    private void HandleVerifyFlow(VerifyFlowActorEvent actorEvent)
    {
        IActorRef? childActor = Context.Child(GetActorName(actorEvent.ConnectId));

        if (!childActor.IsNobody())
            childActor.Forward(actorEvent);
        else
            Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.NotFound(
                    "Verification flow not found. It may have expired or has been completed.")));
    }

    private void HandleTerminated(Terminated msg)
    {
        Log.Information("Verification flow actor {ActorPath} has terminated.", msg.ActorRef.Path);
    }

    private static string GetActorName(uint connectId)
    {
        return $"flow-{connectId}";
    }

    public static Props Build(IActorRef persistor, IActorRef membershipActor, SNSProvider snsProvider,
        ILocalizationProvider localizationProvider)
    {
        return Props.Create(() =>
            new VerificationFlowManagerActor(persistor, membershipActor, snsProvider, localizationProvider));
    }
}