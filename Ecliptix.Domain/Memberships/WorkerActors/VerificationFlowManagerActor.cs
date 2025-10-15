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
    private static readonly ILogger Logger = Log.ForContext<VerificationFlowManagerActor>();

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
                    Logger.Warning(
                        "[verification.flow.manager.force-stop] Cancellation while waiting for termination of ConnectId {ConnectId}",
                        actorEvent.ConnectId);
                    Context.Stop(existingActor);
                }
                catch (Exception ex)
                {
                    Logger.Warning(ex,
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

            Logger.Information("[verification.flow.manager.spawned] ConnectId {ConnectId} Purpose {Purpose}",
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
            string message = _localizationProvider.Localize(VerificationFlowMessageKeys.VerificationFlowNotFound,
                actorEvent.CultureName);
            Sender.Tell(Result<Unit, VerificationFlowFailure>.Err(VerificationFlowFailure.NotFound(message)));

            actorEvent.ChannelWriter.TryComplete();
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
        ILocalizationProvider localizationProvider, IOptions<SecurityConfiguration> securityConfig)
    {
        return Props.Create(() => new VerificationFlowManagerActor(persistor, membershipActor, smsProvider, localizationProvider, securityConfig));
    }
}
