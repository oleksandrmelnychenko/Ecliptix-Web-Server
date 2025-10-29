using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.ActorEvents.MobileNumber;
using Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Providers.Twilio;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Microsoft.Extensions.Options;
using Serilog;

namespace Ecliptix.Domain.Memberships.WorkerActors.VerificationFlow;

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
    private readonly IOptionsMonitor<SecurityConfiguration> _securityConfig;

    private readonly Dictionary<IActorRef, ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>>>
        _flowWriters = new();
    private readonly Dictionary<string, IActorRef> _idempotencyToActor = new();

    public VerificationFlowManagerActor(
        IActorRef persistor,
        IActorRef membershipActor,
        ISmsProvider smsProvider,
        ILocalizationProvider localizationProvider,
        IOptionsMonitor<SecurityConfiguration> securityConfig)
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
        ReceiveAsync<VerifyFlowActorEvent>(HandleVerifyFlowAsync);
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
            IActorRef? idempotencyActor = null;
            if (actorEvent.IdempotencyKey.IsSome &&
                _idempotencyToActor.TryGetValue(actorEvent.IdempotencyKey.Value!, out IActorRef? trackedActor))
            {
                idempotencyActor = trackedActor;
            }

            if (idempotencyActor != null && !idempotencyActor.IsNobody())
            {
                try
                {
                    VerificationFlowActorSettings settings = _securityConfig.CurrentValue.VerificationFlowActor;
                    Task<FlowValidityResponse> validityTask = idempotencyActor.Ask<FlowValidityResponse>(
                        new CheckFlowValidityQuery(),
                        timeout: settings.SessionValidityCheckTimeout);

                    FlowValidityResponse validity = await validityTask;

                    if (validity.IsValid)
                    {
                        Log.Information(
                            "[verification.flow.manager.resume] ConnectId {ConnectId} IdempotencyKey {IdempotencyKey} - Resuming valid session with {RemainingSeconds}s remaining",
                            actorEvent.ConnectId, actorEvent.IdempotencyKey, validity.RemainingSeconds);

                        _flowWriters[idempotencyActor] = actorEvent.ChannelWriter;
                        idempotencyActor.Tell(new ReplaceChannelWriterCommand(actorEvent.ConnectId, actorEvent.ChannelWriter));

                        Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
                        return;
                    }

                    Log.Information(
                        "[verification.flow.manager.expired] ConnectId {ConnectId} IdempotencyKey {IdempotencyKey} - Session expired, creating new flow",
                        actorEvent.ConnectId, actorEvent.IdempotencyKey);
                }
                catch (AskTimeoutException)
                {
                    Log.Warning(
                        "[verification.flow.manager.timeout] ConnectId {ConnectId} IdempotencyKey {IdempotencyKey} - Actor not responding",
                        actorEvent.ConnectId, actorEvent.IdempotencyKey);
                }
                catch (Exception ex)
                {
                    Log.Warning(ex,
                        "[verification.flow.manager.validity-check-failed] ConnectId {ConnectId} IdempotencyKey {IdempotencyKey} - Validity check failed",
                        actorEvent.ConnectId, actorEvent.IdempotencyKey);
                }

                _flowWriters.Remove(idempotencyActor, out _);
                Context.Unwatch(idempotencyActor);
                if (actorEvent.IdempotencyKey.IsSome)
                {
                    _idempotencyToActor.Remove(actorEvent.IdempotencyKey.Value!);
                }

                VerificationFlowActorSettings terminationSettings = _securityConfig.CurrentValue.VerificationFlowActor;
                TimeSpan terminationTimeout = TimeSpan.FromSeconds(
                    Math.Max(terminationSettings.ActorTerminationMinTimeoutSeconds,
                        _securityConfig.CurrentValue.VerificationFlow.ChannelWriteTimeoutSeconds +
                        _securityConfig.CurrentValue.VerificationFlow.OtpExpirationSeconds));

                try
                {
                    Task<bool> gracefulStop = idempotencyActor.GracefulStop(
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
                    Context.Stop(idempotencyActor);
                }
                catch (Exception ex)
                {
                    Log.Warning(ex,
                        "[verification.flow.manager.force-stop] Failed to gracefully stop flow actor for ConnectId {ConnectId}",
                        actorEvent.ConnectId);
                    Context.Stop(idempotencyActor);
                }
            }
            else if (!existingActor.IsNobody())
            {
                _flowWriters.Remove(existingActor, out _);
                Context.Unwatch(existingActor);

                VerificationFlowActorSettings existingTerminationSettings = _securityConfig.CurrentValue.VerificationFlowActor;
                TimeSpan terminationTimeout = TimeSpan.FromSeconds(
                    Math.Max(existingTerminationSettings.ActorTerminationMinTimeoutSeconds,
                        _securityConfig.CurrentValue.VerificationFlow.ChannelWriteTimeoutSeconds +
                        _securityConfig.CurrentValue.VerificationFlow.OtpExpirationSeconds));

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

            if (actorEvent.IdempotencyKey.IsSome)
            {
                _idempotencyToActor[actorEvent.IdempotencyKey.Value!] = newFlowActor;
            }

            Log.Information("[verification.flow.manager.spawned] ConnectId {ConnectId} Purpose {Purpose} IdempotencyKey {IdempotencyKey}",
                actorEvent.ConnectId, actorEvent.Purpose, actorEvent.IdempotencyKey.Match(key => key, () => "none"));

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

    private async Task HandleVerifyFlowAsync(VerifyFlowActorEvent actorEvent)
    {
        IActorRef? childActor = Context.Child(GetActorName(actorEvent.ConnectId));

        if (!childActor.IsNobody())
        {
            childActor.Forward(actorEvent);
        }
        else
        {
            QueryFlowStatusByConnectionIdActorEvent queryEvent = new(
                actorEvent.ConnectId,
                actorEvent.CancellationToken);

            Result<FlowStatusQueryRecord, VerificationFlowFailure> queryResult =
                await _persistor.Ask<Result<FlowStatusQueryRecord, VerificationFlowFailure>>(
                    queryEvent,
                    TimeoutConfiguration.Actor.AskTimeout,
                    actorEvent.CancellationToken);

            if (queryResult.IsErr)
            {
                Log.Warning(
                    "[verification.flow.manager.verify-query-failed] ConnectId {ConnectId} - Query failed",
                    actorEvent.ConnectId);

                Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(queryResult.UnwrapErr()));
                return;
            }

            FlowStatusQueryRecord flowStatus = queryResult.Unwrap();
            VerificationFlowFailure failure;

            if (!flowStatus.IsFound)
            {
                failure = VerificationFlowFailure.NotFound();

                Log.Information(
                    "[verification.flow.manager.verify-not-found] ConnectId {ConnectId} - No flow found",
                    actorEvent.ConnectId);
            }
            else if (flowStatus.Status == VerificationFlowStatus.Expired || flowStatus.ExpiresAt < DateTimeOffset.UtcNow)
            {
                failure = new VerificationFlowFailure(
                    VerificationFlowFailureType.Expired,
                    VerificationFlowMessageKeys.VerificationFlowExpired);

                Log.Information(
                    "[verification.flow.manager.verify-expired] ConnectId {ConnectId} - Session expired",
                    actorEvent.ConnectId);
            }
            else if (flowStatus.Status == VerificationFlowStatus.Verified)
            {
                failure = new VerificationFlowFailure(
                    VerificationFlowFailureType.Validation,
                    "Verification already completed");

                Log.Information(
                    "[verification.flow.manager.verify-already-completed] ConnectId {ConnectId} - Already verified",
                    actorEvent.ConnectId);
            }
            else
            {
                failure = VerificationFlowFailure.NotFound();

                Log.Warning(
                    "[verification.flow.manager.verify-actor-missing] ConnectId {ConnectId} Status {Status} - Flow exists but actor missing",
                    actorEvent.ConnectId, flowStatus.Status);
            }

            Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(failure));
        }
    }

    private void HandleFlowCompletedGracefully(FlowCompletedGracefullyActorEvent actorEvent)
    {
        IActorRef completedActor = actorEvent.ActorRef;
        _flowWriters.Remove(completedActor,
            out ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>>? _);

        string? keyToRemove = null;
        foreach (KeyValuePair<string, IActorRef> kvp in _idempotencyToActor)
        {
            if (kvp.Value.Equals(completedActor))
            {
                keyToRemove = kvp.Key;
                break;
            }
        }

        if (keyToRemove != null)
        {
            _idempotencyToActor.Remove(keyToRemove);
        }
    }

    private void HandleTerminated(Terminated terminatedMessage)
    {
        IActorRef deadActor = terminatedMessage.ActorRef;

        string? keyToRemove = null;
        foreach (KeyValuePair<string, IActorRef> kvp in _idempotencyToActor)
        {
            if (kvp.Value.Equals(deadActor))
            {
                keyToRemove = kvp.Key;
                break;
            }
        }

        if (keyToRemove != null)
        {
            _idempotencyToActor.Remove(keyToRemove);
        }

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
        VerificationFlowActorSettings settings = _securityConfig.CurrentValue.VerificationFlowActor;
        return new OneForOneStrategy(
            maxNrOfRetries: 3,
            withinTimeRange: settings.CircuitBreakerWithinTimeRange,
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
        ILocalizationProvider localizationProvider, IOptionsMonitor<SecurityConfiguration> securityConfig)
    {
        return Props.Create(() => new VerificationFlowManagerActor(persistor, membershipActor, smsProvider, localizationProvider, securityConfig));
    }
}
