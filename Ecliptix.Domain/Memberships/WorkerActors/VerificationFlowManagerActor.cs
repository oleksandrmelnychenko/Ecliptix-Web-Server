using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Providers.Twilio;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Membership;
using Serilog;

namespace Ecliptix.Domain.Memberships.WorkerActors;

public record FlowCompletedGracefullyActorEvent(IActorRef ActorRef);

public class VerificationFlowManagerActor : ReceiveActor
{
    private readonly ILocalizationProvider _localizationProvider;
    private readonly IActorRef _membershipActor;
    private readonly IActorRef _persistor;
    private readonly ISmsProvider _smsProvider;

    private readonly Dictionary<IActorRef, ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>>>
        _flowWriters = new();

    public VerificationFlowManagerActor(
        IActorRef persistor,
        IActorRef membershipActor,
        ISmsProvider smsProvider,
        ILocalizationProvider localizationProvider)
    {
        _persistor = persistor;
        _membershipActor = membershipActor;
        _smsProvider = smsProvider;
        _localizationProvider = localizationProvider;

        Become(Ready);
    }

    private void Ready()
    {
        Receive<InitiateVerificationFlowActorEvent>(HandleInitiateFlow);
        Receive<VerifyFlowActorEvent>(HandleVerifyFlow);
        Receive<Terminated>(HandleTerminated);
        Receive<EnsureMobileNumberActorEvent>(actorEvent => _persistor.Forward(actorEvent));
        Receive<VerifyMobileForSecretKeyRecoveryActorEvent>(actorEvent => _persistor.Forward(actorEvent));
        Receive<FlowCompletedGracefullyActorEvent>(HandleFlowCompletedGracefully);
    }

    private void HandleInitiateFlow(InitiateVerificationFlowActorEvent actorEvent)
    {
        string baseActorName = GetActorName(actorEvent.ConnectId);
        IActorRef? childActor = Context.Child(baseActorName);

        if (actorEvent.RequestType == InitiateVerificationRequest.Types.Type.SendOtp)
        {
            if (!childActor.IsNobody())
            {

                _flowWriters.Remove(childActor);
                Context.Unwatch(childActor);
                Context.Stop(childActor);
            }

            IActorRef? newFlowActor = Context.ActorOf(VerificationFlowActor.Build(
                actorEvent.ConnectId,
                actorEvent.MobileNumberIdentifier,
                actorEvent.AppDeviceIdentifier,
                actorEvent.Purpose,
                actorEvent.ChannelWriter,
                _persistor,
                _membershipActor,
                _smsProvider,
                _localizationProvider,
                actorEvent.CultureName
            ), baseActorName);

            Context.Watch(newFlowActor);
            _flowWriters.TryAdd(newFlowActor, actorEvent.ChannelWriter);

            Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
        }
        else
        {
            if (!childActor.IsNobody())
            {
                _flowWriters[childActor] = actorEvent.ChannelWriter;
                childActor.Forward(actorEvent);
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
                VerificationFlowFailure.NotFound()));
    }

    private void HandleFlowCompletedGracefully(FlowCompletedGracefullyActorEvent actorEvent)
    {
        IActorRef completedActor = actorEvent.ActorRef;
        _flowWriters.Remove(completedActor,
            out ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>>? _);
    }

    private void HandleTerminated(Terminated terminatedMessage)
    {
        IActorRef deadActor = terminatedMessage.ActorRef;
        if (_flowWriters.Remove(deadActor,
                out ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>>? writer))
        {
            if (terminatedMessage is { ExistenceConfirmed: true, AddressTerminated: false })
            {

                VerificationFlowFailure failure = VerificationFlowFailure.Generic(
                    "The verification process was terminated due to an internal server error."
                );

                bool writeSuccess =
                    writer.TryWrite(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Err(failure));
                if (!writeSuccess)
                {

                }

                bool completeSuccess = writer.TryComplete();
                if (!completeSuccess)
                {

                }
            }
        }
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return new OneForOneStrategy(
            maxNrOfRetries: 3,
            withinTimeRange: TimeSpan.FromMinutes(1),
            decider: Decider.From(ChildFailureDecider));
    }

    private static Directive ChildFailureDecider(Exception ex)
    {
        switch (ex)
        {
            case ArgumentException argEx:

                return Directive.Stop;

            case ActorInitializationException initEx:

                return Directive.Stop;

            case IOException ioEx:

                return Directive.Restart;

            default:

                return Directive.Stop;
        }
    }

    private static string GetActorName(uint connectId) =>
        $"flow-{connectId}";

    public static Props Build(IActorRef persistor, IActorRef membershipActor, ISmsProvider smsProvider,
        ILocalizationProvider localizationProvider)
    {
        return Props.Create(() => new VerificationFlowManagerActor(persistor, membershipActor, smsProvider, localizationProvider));
    }
}