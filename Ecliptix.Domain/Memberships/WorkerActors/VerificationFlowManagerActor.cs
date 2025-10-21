using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Providers.Twilio;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Ecliptix.Protobuf.Membership;
using Microsoft.Extensions.Options;
using Serilog;

namespace Ecliptix.Domain.Memberships.WorkerActors;

public record FlowCompletedGracefullyActorEvent(IActorRef ActorRef);

public sealed class FlowTerminationAcknowledged
{
    public static readonly FlowTerminationAcknowledged Instance = new();
    private FlowTerminationAcknowledged()
    {
    }
}

public sealed class VerificationFlowManagerActor : ReceiveActor
{
    private readonly ILocalizationProvider _localizationProvider;
    private readonly IActorRef _membershipActor;
    private readonly IActorRef _persistor;
    private readonly ISmsProvider _smsProvider;
    private readonly IOptions<SecurityConfiguration> _securityConfig;

    private readonly Dictionary<IActorRef, ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>>>
        _flowWriters = new();

    public VerificationFlowManagerActor(
        IActorRef persistor,
        IActorRef membershipActor,
        ISmsProvider smsProvider,
        ILocalizationProvider localizationProvider,
        IOptions<SecurityConfiguration> securityConfig)
    {
        _persistor = persistor;
        _membershipActor = membershipActor;
        _smsProvider = smsProvider;
        _localizationProvider = localizationProvider;
        _securityConfig = securityConfig;

        Become(Ready);
    }

    private void Ready()
    {
        ReceiveAsync<InitiateVerificationFlowActorEvent>(HandleInitiateFlowAsync);
        Receive<VerifyFlowActorEvent>(HandleVerifyFlow);
        Receive<Terminated>(HandleTerminated);
        Receive<EnsureMobileNumberActorEvent>(actorEvent => _persistor.Forward(actorEvent));
        Receive<VerifyMobileForSecretKeyRecoveryActorEvent>(actorEvent => _persistor.Forward(actorEvent));
        Receive<CheckMobileNumberAvailabilityActorEvent>(actorEvent => _persistor.Forward(actorEvent));
        Receive<FlowCompletedGracefullyActorEvent>(HandleFlowCompletedGracefully);
    }

    private async Task HandleInitiateFlowAsync(InitiateVerificationFlowActorEvent actorEvent)
    {
        string baseActorName = GetActorName(actorEvent.ConnectId);
        IActorRef? existingActor = Context.Child(baseActorName);

        if (actorEvent.RequestType == InitiateVerificationRequest.Types.Type.SendOtp)
        {
            if (!existingActor.IsNobody())
            {
                _flowWriters.Remove(existingActor, out _);
                Context.Unwatch(existingActor);

                TimeSpan terminationTimeout = TimeSpan.FromSeconds(
                    Math.Max(5,
                        _securityConfig.Value.VerificationFlow.ChannelWriteTimeoutSeconds +
                        _securityConfig.Value.VerificationFlow.OtpExpirationSeconds));

                try
                {
                    Task<bool> gracefulStop = existingActor.GracefulStop(
                        terminationTimeout,
                        new PrepareForTerminationMessage());

                    if (actorEvent.CancellationToken.CanBeCanceled)
                    {
                        await gracefulStop.WaitAsync(actorEvent.CancellationToken);
                    }
                    else
                    {
                        await gracefulStop;
                    }
                }
                catch (OperationCanceledException)
                {
                    Log.Warning(
                        "[verification.flow.manager.force-stop] Cancellation while waiting for termination of ConnectId {ConnectId}",
                        actorEvent.ConnectId);
                    Context.Stop(existingActor);
                }
                catch (Exception ex)
                {
                    Log.Warning(ex,
                        "[verification.flow.manager.force-stop] Failed to gracefully stop flow actor for ConnectId {ConnectId}",
                        actorEvent.ConnectId);
                    Context.Stop(existingActor);
                }
            }

            Props props = VerificationFlowActor.Build(
                actorEvent.ConnectId,
                actorEvent.MobileNumberIdentifier,
                actorEvent.AppDeviceIdentifier,
                actorEvent.Purpose,
                actorEvent.ChannelWriter,
                _persistor,
                _membershipActor,
                _smsProvider,
                _localizationProvider,
                actorEvent.CultureName,
                _securityConfig,
                actorEvent.ActivityContext,
                actorEvent.CancellationToken);

            IActorRef newFlowActor = Context.ActorOf(props, baseActorName);

            Context.Watch(newFlowActor);
            _flowWriters[newFlowActor] = actorEvent.ChannelWriter;

            Log.Information("[verification.flow.manager.spawned] ConnectId {ConnectId} Purpose {Purpose}",
                actorEvent.ConnectId, actorEvent.Purpose);

            Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
            return;
        }

        if (!existingActor.IsNobody())
        {
            _flowWriters[existingActor] = actorEvent.ChannelWriter;
            existingActor.Forward(actorEvent);
        }
        else
        {
            Props props = VerificationFlowActor.Build(
                actorEvent.ConnectId,
                actorEvent.MobileNumberIdentifier,
                actorEvent.AppDeviceIdentifier,
                actorEvent.Purpose,
                actorEvent.ChannelWriter,
                _persistor,
                _membershipActor,
                _smsProvider,
                _localizationProvider,
                actorEvent.CultureName,
                _securityConfig,
                actorEvent.ActivityContext,
                actorEvent.CancellationToken);

            IActorRef newFlowActor = Context.ActorOf(props, baseActorName);
            Context.Watch(newFlowActor);
            _flowWriters[newFlowActor] = actorEvent.ChannelWriter;

            newFlowActor.Forward(actorEvent);
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
                VerificationFlowFailure.NotFound()));
        }
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
                    Log.Warning("[verification.flow.manager.channel-write-failed] Unable to notify client for terminated actor {ActorPath}",
                        deadActor.Path);
                }

                bool completeSuccess = writer.TryComplete();
                if (!completeSuccess)
                {
                    Log.Warning("[verification.flow.manager.channel-complete-failed] Channel completion failed for terminated actor {ActorPath}",
                        deadActor.Path);
                }
            }
        }
        else
        {
            Log.Debug("[verification.flow.manager.terminated-untracked] Received termination for untracked actor {ActorPath}",
                deadActor.Path);
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
        return ex switch
        {
            ArgumentException => Directive.Stop,
            ActorInitializationException => Directive.Stop,
            IOException => Directive.Restart,
            _ => Directive.Stop
        };
    }

    private static string GetActorName(uint connectId) =>
        $"flow-{connectId}";

    public static Props Build(IActorRef persistor, IActorRef membershipActor, ISmsProvider smsProvider,
        ILocalizationProvider localizationProvider, IOptions<SecurityConfiguration> securityConfig)
    {
        return Props.Create(() => new VerificationFlowManagerActor(persistor, membershipActor, smsProvider, localizationProvider, securityConfig));
    }
}
