using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Memberships;
using Ecliptix.IdentityAccess.Domain.Actors.Membership;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Providers.Twilio;
using Ecliptix.IdentityAccess.Domain.Services;
using Ecliptix.Protobuf.Membership;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Configuration;
using Microsoft.Extensions.Options;
using Serilog;

namespace Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow;

public sealed class VerificationFlowManagerActor : ReceiveActor
{
    private const int IdempotencyTtlMinutes = 30;
    private static readonly TimeSpan IdempotencyCleanupInterval = TimeSpan.FromMinutes(5);

    private readonly ILocalizationService _localizationService;
    private readonly IActorRef _membershipActor;
    private readonly IActorRef _persistorActor;
    private readonly ISmsProvider _smsProvider;
    private readonly IOptionsMonitor<SecurityConfiguration> _securityConfig;

    private readonly Dictionary<IActorRef, ChannelWriter<Result<OtpCountdownUpdate, VerificationFlowFailure>>>
        _flowWriters = new();

    private readonly Dictionary<string, (IActorRef Actor, DateTimeOffset CreatedAt)> _idempotencyToActor = new();
    private ICancelable? _idempotencyCleanupTimer;

    public VerificationFlowManagerActor(
        IActorRef persistor,
        IActorRef membershipActor,
        ISmsProvider smsProvider,
        ILocalizationService localizationService,
        IOptionsMonitor<SecurityConfiguration> securityConfig)
    {
        _persistorActor = persistor;
        _membershipActor = membershipActor;
        _smsProvider = smsProvider;
        _localizationService = localizationService;
        _securityConfig = securityConfig;

        Become(Ready);
    }

    protected override void PreStart()
    {
        base.PreStart();
        _idempotencyCleanupTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
            IdempotencyCleanupInterval,
            IdempotencyCleanupInterval,
            Self,
            CleanupStaleIdempotencyKeys.Instance,
            ActorRefs.NoSender);
    }

    protected override void PostStop()
    {
        _idempotencyCleanupTimer?.Cancel();
        base.PostStop();
    }

    private void Ready()
    {
        ReceiveAsync<InitiateVerificationFlowCommand>(HandleInitiateFlowAsync);
        ReceiveAsync<VerifyFlowCommand>(HandleVerifyFlowAsync);
        Receive<Terminated>(HandleTerminated);
        Receive<ValidateMobileNumberCommand>(actorEvent => _persistorActor.Forward(actorEvent));
        Receive<VerifyMobileForSecretKeyRecoveryCommand>(actorEvent => _persistorActor.Forward(actorEvent));
        Receive<ExistsMobileNumberQuery>(actorEvent => _persistorActor.Forward(actorEvent));
        Receive<FlowCompletedGracefullyEvent>(HandleFlowCompletedGracefully);
        Receive<CleanupStaleIdempotencyKeys>(HandleCleanupStaleIdempotencyKeys);
    }

    private async Task HandleInitiateFlowAsync(InitiateVerificationFlowCommand actorEvent)
    {
        string baseActorName = GetActorName(actorEvent.ConnectId);
        IActorRef? existingActor = Context.Child(baseActorName);

        if (actorEvent.RequestType == OtpVerificationRequest.Types.Type.OtpRequestTypeSend)
        {
            await HandleSendOtpRequestAsync(actorEvent, existingActor, baseActorName);
        }
        else
        {
            HandleOtherRequests(actorEvent, existingActor, baseActorName);
        }
    }

    private async Task HandleSendOtpRequestAsync(
        InitiateVerificationFlowCommand actorEvent,
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
            await TerminateFlowActorAsync(actorToCleanup, actorEvent.IdempotencyKey, actorEvent.CancellationToken);
        }

        if (!existingActor.IsNobody() && (actorToCleanup == null || !existingActor!.Equals(actorToCleanup)))
        {
            await TerminateFlowActorAsync(existingActor!, Option<string>.None, actorEvent.CancellationToken);
        }

        IActorRef? stillExists = Context.Child(baseActorName);
        if (!stillExists.IsNobody())
        {
            Sender.Tell(Result<Unit, VerificationFlowFailure>.Err(
                new VerificationFlowFailure(
                    VerificationFlowFailureType.Generic,
                    VerificationFlowMessageKeys.InitiateFlowFailed
                )));
            return;
        }

        IActorRef newFlowActor = SpawnNewFlowActor(actorEvent, baseActorName);

        if (actorEvent.IdempotencyKey.IsSome)
        {
            _idempotencyToActor[actorEvent.IdempotencyKey.Value!] = (newFlowActor, DateTimeOffset.UtcNow);
        }

        Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
    }

    private void HandleOtherRequests(
        InitiateVerificationFlowCommand actorEvent,
        IActorRef? existingActor,
        string baseActorName)
    {
        if (!existingActor.IsNobody())
        {
            _flowWriters[existingActor!] = actorEvent.ChannelWriter;
            existingActor.Forward(actorEvent);
        }
        else
        {
            IActorRef newFlowActor = SpawnNewFlowActor(actorEvent, baseActorName);
            newFlowActor.Forward(actorEvent);
        }
    }

    private async Task<(bool Resumed, IActorRef? ActorFound)> TryResumeIdempotentSessionAsync(
        InitiateVerificationFlowCommand actorEvent)
    {
        if (!actorEvent.IdempotencyKey.IsSome ||
            !_idempotencyToActor.TryGetValue(actorEvent.IdempotencyKey.Value!, out (IActorRef Actor, DateTimeOffset CreatedAt) entry) ||
            entry.Actor.IsNobody())
        {
            return (false, null);
        }

        IActorRef trackedActor = entry.Actor;

        try
        {
            VerificationFlowActorSettings settings = _securityConfig.CurrentValue.VerificationFlowActor;
            FlowValidityResponse validity = await trackedActor.Ask<FlowValidityResponse>(
                new IsFlowValidQuery(),
                timeout: settings.SessionValidityCheckTimeout);

            if (validity.IsValid)
            {
                _flowWriters[trackedActor] = actorEvent.ChannelWriter;
                trackedActor.Tell(new ReplaceChannelWriterCommand(actorEvent.ConnectId, actorEvent.ChannelWriter));
                return (true, trackedActor);
            }

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

    private async Task TerminateFlowActorAsync(IActorRef actorToStop,
        Option<string> idempotencyKey,
        CancellationToken cancellationToken)
    {
        string actorName = actorToStop.Path.Name;

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

        bool gracefulStopSucceeded = false;
        try
        {
            Task<bool> gracefulStop = actorToStop.GracefulStop(
                terminationTimeout,
                new PrepareForTerminationMessage());

            if (cancellationToken.CanBeCanceled)
            {
                gracefulStopSucceeded = await gracefulStop.WaitAsync(cancellationToken);
            }
            else
            {
                gracefulStopSucceeded = await gracefulStop;
            }

            if (gracefulStopSucceeded)
            {
                Log.Information("[verification.flow.manager.graceful-stop] Successfully stopped {ActorName}",
                    actorName);
            }
        }
        catch (OperationCanceledException)
        {
            Log.Debug(
                "[verification.flow.manager.force-stop] Cancellation while waiting for termination of {ActorName}, using PoisonPill",
                actorName);
            actorToStop.Tell(PoisonPill.Instance);
        }
        catch (Exception ex)
        {
            Log.Warning(ex,
                "[verification.flow.manager.force-stop] Graceful stop failed for {ActorName}, using PoisonPill",
                actorName);
            actorToStop.Tell(PoisonPill.Instance);
        }

        if (!gracefulStopSucceeded)
        {
            TimeSpan waitTimeout = TimeSpan.FromSeconds(5);
            bool removed = await WaitForActorRemovalAsync(actorName, waitTimeout, cancellationToken);

            if (removed)
            {
                Log.Information("[verification.flow.manager.force-stop-success] {ActorName} removed after PoisonPill",
                    actorName);
            }
        }
    }

    private static async Task<bool> WaitForActorRemovalAsync(
        string actorName,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        const int pollIntervalMs = 50;

        while (DateTime.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
        {
            if (Context.Child(actorName).IsNobody())
            {
                Log.Debug("[verification.flow.manager.actor-removed] {ActorName} successfully removed from hierarchy",
                    actorName);
                return true;
            }

            try
            {
                await Task.Delay(pollIntervalMs, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                Log.Debug("[verification.flow.manager.wait-cancelled] Wait for {ActorName} removal was cancelled",
                    actorName);
                return false;
            }
        }

        bool finalCheck = Context.Child(actorName).IsNobody();
        if (!finalCheck)
        {
            Log.Warning(
                "[verification.flow.manager.removal-timeout] {ActorName} still exists after {TimeoutSeconds}s timeout",
                actorName, timeout.TotalSeconds);
        }

        return finalCheck;
    }

    private IActorRef SpawnNewFlowActor(
        InitiateVerificationFlowCommand actorEvent,
        string baseActorName)
    {
        Props props = VerificationFlowActor.Build(
            actorEvent.ConnectId,
            actorEvent.MobileNumberIdentifier,
            actorEvent.AppDeviceIdentifier,
            actorEvent.Purpose,
            actorEvent.ChannelWriter,
            _persistorActor,
            _membershipActor,
            _smsProvider,
            _localizationService,
            actorEvent.CultureName,
            _securityConfig,
            actorEvent.CancellationToken);

        IActorRef newFlowActor = Context.ActorOf(props, baseActorName);

        Context.Watch(newFlowActor);
        _flowWriters[newFlowActor] = actorEvent.ChannelWriter;

        return newFlowActor;
    }

    private async Task HandleVerifyFlowAsync(VerifyFlowCommand actorEvent)
    {
        IActorRef? childActor = Context.Child(GetActorName(actorEvent.ConnectId));

        if (!childActor.IsNobody())
        {
            childActor.Forward(actorEvent);
        }
        else
        {
            GetFlowStatusByConnectionIdQuery queryEvent = new(
                actorEvent.ConnectId,
                actorEvent.CancellationToken);

            Result<FlowStatusQueryRecord, VerificationFlowFailure> queryResult =
                await _persistorActor.Ask<Result<FlowStatusQueryRecord, VerificationFlowFailure>>(
                    queryEvent,
                    TimeoutConfiguration.Actor.AskTimeout,
                    actorEvent.CancellationToken);

            if (queryResult.IsErr)
            {
                Log.Warning(
                    "[verification.flow.manager.verify-query-failed] ConnectId {ConnectId} - Query failed",
                    actorEvent.ConnectId);

                Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Err(queryResult.UnwrapErr()));
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
            else if (flowStatus.Status == VerificationFlowStatus.Expired ||
                     flowStatus.ExpiresAt < DateTimeOffset.UtcNow)
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

            Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Err(failure));
        }
    }

    private void HandleFlowCompletedGracefully(FlowCompletedGracefullyEvent actorEvent)
    {
        IActorRef completedActor = actorEvent.ActorRef;
        _flowWriters.Remove(completedActor,
            out ChannelWriter<Result<OtpCountdownUpdate, VerificationFlowFailure>>? _);

        KeyValuePair<string, (IActorRef Actor, DateTimeOffset CreatedAt)> entryToRemove = _idempotencyToActor
            .FirstOrDefault(kvp => kvp.Value.Actor.Equals(completedActor));

        if (entryToRemove.Key != null)
        {
            _idempotencyToActor.Remove(entryToRemove.Key);
        }
    }

    private void HandleTerminated(Terminated terminatedMessage)
    {
        IActorRef deadActor = terminatedMessage.ActorRef;

        string? keyToRemove = _idempotencyToActor
            .FirstOrDefault(kvp => kvp.Value.Actor.Equals(deadActor))
            .Key;

        if (keyToRemove != null)
        {
            _idempotencyToActor.Remove(keyToRemove);
        }

        if (_flowWriters.Remove(deadActor,
                out ChannelWriter<Result<OtpCountdownUpdate, VerificationFlowFailure>>? writer))
        {
            if (terminatedMessage is { ExistenceConfirmed: true, AddressTerminated: false })
            {
                VerificationFlowFailure failure = VerificationFlowFailure.Generic(
                    "The verification process was terminated due to an internal server error."
                );

                bool writeSuccess =
                    writer.TryWrite(Result<OtpCountdownUpdate, VerificationFlowFailure>.Err(failure));
                if (!writeSuccess)
                {
                    Log.Warning(
                        "[verification.flow.manager.channel-write-failed] Unable to notify client for terminated actor {ActorPath}",
                        deadActor.Path);
                }

                bool completeSuccess = writer.TryComplete();
                if (!completeSuccess)
                {
                    Log.Warning(
                        "[verification.flow.manager.channel-complete-failed] Channel completion failed for terminated actor {ActorPath}",
                        deadActor.Path);
                }
            }
        }
        else
        {
            Log.Debug(
                "[verification.flow.manager.terminated-untracked] Received termination for untracked actor {ActorPath}",
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

    private void HandleCleanupStaleIdempotencyKeys(CleanupStaleIdempotencyKeys _)
    {
        DateTimeOffset cutoff = DateTimeOffset.UtcNow.AddMinutes(-IdempotencyTtlMinutes);
        List<string> keysToRemove = [];

        foreach (KeyValuePair<string, (IActorRef Actor, DateTimeOffset CreatedAt)> kvp in _idempotencyToActor)
        {
            if (kvp.Value.CreatedAt < cutoff || kvp.Value.Actor.IsNobody())
            {
                keysToRemove.Add(kvp.Key);
            }
        }

        foreach (string key in keysToRemove)
        {
            _idempotencyToActor.Remove(key);
        }

        if (keysToRemove.Count > 0)
        {
            Log.Debug(
                "[verification.flow.manager.cleanup] Removed {Count} stale idempotency keys",
                keysToRemove.Count);
        }
    }

    public static Props Build(IActorRef persistor, IActorRef membershipActor, ISmsProvider smsProvider,
        ILocalizationService localizationService, IOptionsMonitor<SecurityConfiguration> securityConfig)
    {
        return Props.Create(() =>
            new VerificationFlowManagerActor(persistor, membershipActor, smsProvider, localizationService,
                securityConfig));
    }

    private sealed class CleanupStaleIdempotencyKeys
    {
        public static readonly CleanupStaleIdempotencyKeys Instance = new();
        private CleanupStaleIdempotencyKeys() { }
    }
}
