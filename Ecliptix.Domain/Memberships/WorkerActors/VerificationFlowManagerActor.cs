using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Providers.Twilio;
using Ecliptix.Domain.Utilities;
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
        Receive<EnsurePhoneNumberActorEvent>(actorEvent => _persistor.Forward(actorEvent));
        Receive<VerifyPhoneForSecretKeyRecoveryActorEvent>(actorEvent => _persistor.Forward(actorEvent));
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
                Log.Information("Cleaning up existing flow actor for ConnectId {ConnectId} before creating new one",
                    actorEvent.ConnectId);

                _flowWriters.Remove(childActor);
                Context.Unwatch(childActor);
                Context.Stop(childActor);
            }

            IActorRef? newFlowActor = Context.ActorOf(VerificationFlowActor.Build(
                actorEvent.ConnectId,
                actorEvent.PhoneNumberIdentifier,
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
        if (_flowWriters.TryGetValue(completedActor,
                out ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>>? _))
        {
            _flowWriters.Remove(completedActor);
            Log.Debug("Verification flow completed gracefully for actor {ActorPath}", completedActor.Path);
        }
        else
        {
            Log.Debug("Received FlowCompletedGracefullyActorEvent for untracked actor: {ActorPath}", completedActor.Path);
        }
    }

    private void HandleTerminated(Terminated terminatedMessage)
    {
        IActorRef deadActor = terminatedMessage.ActorRef;
        if (_flowWriters.TryGetValue(deadActor,
                out ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>>? writer))
        {
            _flowWriters.Remove(deadActor);
            if (terminatedMessage is { ExistenceConfirmed: true, AddressTerminated: false })
            {
                Log.Warning(
                    "Child actor {ActorPath} was terminated unexpectedly (crashed). Notifying the client channel",
                    deadActor.Path);

                VerificationFlowFailure failure = VerificationFlowFailure.Generic(
                    "The verification process was terminated due to an internal server error."
                );

                bool writeSuccess =
                    writer.TryWrite(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Err(failure));
                if (!writeSuccess)
                {
                    Log.Error(
                        "Failed to write error to channel for actor {ActorPath}. Channel may be completed or faulted",
                        deadActor.Path);
                }

                bool completeSuccess = writer.TryComplete();
                if (!completeSuccess)
                {
                    Log.Warning("Failed to complete channel for terminated actor {ActorPath}", deadActor.Path);
                }
            }
        }
        else
        {
            Log.Debug("Received Terminated message for an untracked actor: {ActorPath}", deadActor.Path);
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
                Log.Error(argEx,
                    "VerificationFlowActor failed with an invalid state (ArgumentException). Stopping the actor to prevent further issues");
                return Directive.Stop;

            case ActorInitializationException initEx:
                Log.Error(initEx, "VerificationFlowActor failed during its initialization. Stopping the actor");
                return Directive.Stop;

            case IOException ioEx:
                Log.Warning(ioEx, "VerificationFlowActor encountered a transient IO error. Restarting the actor");
                return Directive.Restart;

            default:
                Log.Error(ex,
                    "VerificationFlowActor encountered an unhandled exception. Stopping the actor to prevent further issues");
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