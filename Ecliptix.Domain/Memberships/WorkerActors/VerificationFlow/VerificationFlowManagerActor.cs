using System.Threading.Channels;
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
            await HandleSendOtpRequestAsync(actorEvent, existingActor, baseActorName);
        }
        else
        {
            HandleOtherRequests(actorEvent, existingActor, baseActorName);
        }
    }

    private async Task HandleSendOtpRequestAsync(
        InitiateVerificationFlowActorEvent actorEvent,
        IActorRef? existingActor,
        string baseActorName)
    {
        (bool resumed, IActorRef? actorToCleanup) = await TryResumeIdempotentSessionAsync(actorEvent);
        if (resumed)
        {
            Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
            return;
        }

        if (actorToCleanup != null)
        {
            Log.Information("[verification.flow.manager.cleanup] Cleaning up invalid idempotent flow. ConnectId {ConnectId}", actorEvent.ConnectId);
            await TerminateFlowActorAsync(actorToCleanup, actorEvent.IdempotencyKey, actorEvent.CancellationToken);
        }

        if (!existingActor.IsNobody() && (actorToCleanup == null || !existingActor.Equals(actorToCleanup)))
        {
            Log.Information("[verification.flow.manager.cleanup] Cleaning up existing (non-idempotent) flow. ConnectId {ConnectId}", actorEvent.ConnectId);
            await TerminateFlowActorAsync(existingActor, Option<string>.None, actorEvent.CancellationToken);
        }

        IActorRef newFlowActor = SpawnNewFlowActor(actorEvent, baseActorName);

        if (actorEvent.IdempotencyKey.IsSome)
        {
            _idempotencyToActor[actorEvent.IdempotencyKey.Value!] = newFlowActor;
        }

        Log.Information("[verification.flow.manager.spawned] ConnectId {ConnectId} Purpose {Purpose} IdempotencyKey {IdempotencyKey}",
            actorEvent.ConnectId, actorEvent.Purpose, actorEvent.IdempotencyKey.Match(key => key, () => "none"));

        Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
    }

    private void HandleOtherRequests(
        InitiateVerificationFlowActorEvent actorEvent,
        IActorRef? existingActor,
        string baseActorName)
    {
        if (!existingActor.IsNobody())
        {
            _flowWriters[existingActor] = actorEvent.ChannelWriter;
            existingActor.Forward(actorEvent);
        }
        else
        {
            IActorRef newFlowActor = SpawnNewFlowActor(actorEvent, baseActorName);
            newFlowActor.Forward(actorEvent);
        }
    }

    private async Task<(bool Resumed, IActorRef? ActorFound)> TryResumeIdempotentSessionAsync(
        InitiateVerificationFlowActorEvent actorEvent)
    {
        if (!actorEvent.IdempotencyKey.IsSome)
        {
            return (false, null);
        }

        if (!_idempotencyToActor.TryGetValue(actorEvent.IdempotencyKey.Value!, out IActorRef? trackedActor) ||
            trackedActor.IsNobody())
        {
            return (false, null);
        }

        try
        {
            VerificationFlowActorSettings settings = _securityConfig.CurrentValue.VerificationFlowActor;
            FlowValidityResponse validity = await trackedActor.Ask<FlowValidityResponse>(
                new CheckFlowValidityQuery(),
                timeout: settings.SessionValidityCheckTimeout);

            if (validity.IsValid)
            {
                Log.Information(
                    "[verification.flow.manager.resume] ConnectId {ConnectId} IdempotencyKey {IdempotencyKey} - Resuming valid session with {RemainingSeconds}s remaining",
                    actorEvent.ConnectId, actorEvent.IdempotencyKey, validity.RemainingSeconds);

                _flowWriters[trackedActor] = actorEvent.ChannelWriter;
                trackedActor.Tell(new ReplaceChannelWriterCommand(actorEvent.ConnectId, actorEvent.ChannelWriter));
                return (true, trackedActor);
            }

            Log.Information(
                "[verification.flow.manager.expired] ConnectId {ConnectId} IdempotencyKey {IdempotencyKey} - Session expired, creating new flow",
                actorEvent.ConnectId, actorEvent.IdempotencyKey);

            return (false, trackedActor);
        }
        catch (AskTimeoutException ex)
        {
            Log.Warning(ex,
                "[verification.flow.manager.timeout] ConnectId {ConnectId} IdempotencyKey {IdempotencyKey} - Actor not responding",
                actorEvent.ConnectId, actorEvent.IdempotencyKey);
        }
        catch (Exception ex)
        {
            Log.Warning(ex,
                "[verification.flow.manager.validity-check-failed] ConnectId {ConnectId} IdempotencyKey {IdempotencyKey} - Validity check failed",
                actorEvent.ConnectId, actorEvent.IdempotencyKey);
        }

        return (false, trackedActor);
    }

    private async Task TerminateFlowActorAsync(
        IActorRef actorToStop,
        Option<string> idempotencyKey,
        CancellationToken cancellationToken)
    {
        _flowWriters.Remove(actorToStop, out _);
        Context.Unwatch(actorToStop);
        if (idempotencyKey.IsSome)
        {
            _idempotencyToActor.Remove(idempotencyKey.Value!);
        }

        VerificationFlowActorSettings settings = _securityConfig.CurrentValue.VerificationFlowActor;
        TimeSpan terminationTimeout = TimeSpan.FromSeconds(
            Math.Max(settings.ActorTerminationMinTimeoutSeconds,
                _securityConfig.CurrentValue.VerificationFlow.ChannelWriteTimeoutSeconds +
                _securityConfig.CurrentValue.VerificationFlow.OtpExpirationSeconds));

        try
        {
            Task<bool> gracefulStop = actorToStop.GracefulStop(
                terminationTimeout,
                new PrepareForTerminationMessage());

            if (cancellationToken.CanBeCanceled)
            {
                await gracefulStop.WaitAsync(cancellationToken);
            }
            else
            {
                await gracefulStop;
            }
        }
        catch (OperationCanceledException ex)
        {
            Log.Debug(ex,
                "[verification.flow.manager.force-stop] Cancellation while waiting for termination of {ActorPath}",
                actorToStop.Path);
            Context.Stop(actorToStop);
        }
        catch (Exception ex)
        {
            Log.Warning(ex,
                "[verification.flow.manager.force-stop] Failed to gracefully stop flow actor {ActorPath}",
                actorToStop.Path);
            Context.Stop(actorToStop);
        }
    }

    private IActorRef SpawnNewFlowActor(
        InitiateVerificationFlowActorEvent actorEvent,
        string baseActorName)
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

        return newFlowActor;
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

        KeyValuePair<string, IActorRef> entryToRemove = _idempotencyToActor
            .FirstOrDefault(kvp => kvp.Value.Equals(completedActor));

        if (entryToRemove.Key != null)
        {
            _idempotencyToActor.Remove(entryToRemove.Key);
        }
    }

    private void HandleTerminated(Terminated terminatedMessage)
    {
        IActorRef deadActor = terminatedMessage.ActorRef;

        string? keyToRemove = _idempotencyToActor
            .FirstOrDefault(kvp => kvp.Value.Equals(deadActor))
            .Key;

        if (keyToRemove != null)
        {
            _idempotencyToActor.Remove(keyToRemove);
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
