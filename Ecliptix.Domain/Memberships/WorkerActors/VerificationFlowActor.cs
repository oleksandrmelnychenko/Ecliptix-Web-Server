using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using Akka.Actor;
using Akka.Persistence;
using Ecliptix.Utilities.Configuration;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Providers.Twilio;
using Ecliptix.Domain.Memberships.Instrumentation;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Membership;
using Google.Protobuf;
using Microsoft.Extensions.Options;
using Serilog;

namespace Ecliptix.Domain.Memberships.WorkerActors;

public record ProtocolCleanupRequiredEvent(uint ConnectId);

public record SessionExpiredMessageDeliveredEvent(uint ConnectId);

public record FallbackCleanupEvent();

public sealed class VerificationFlowActor : ReceivePersistentActor, IWithStash
{
    private readonly VerificationFlowTimeouts _timeouts;

    private readonly uint _connectId;
    private readonly string _cultureName;
    private readonly ILocalizationProvider _localizationProvider;
    private readonly IActorRef _membershipActor;
    private readonly IActorRef _persistor;
    private readonly Guid _phoneNumberIdentifier;
    private readonly ISmsProvider _smsProvider;
    private OneTimePassword? _activeOtp;
    private uint _activeOtpRemainingSeconds;
    private readonly Activity? _activity;
    private CancellationToken _currentRequestCancellationToken;
    private bool _writerCompleted;
    private long _otpSendAttempts;
    private readonly KeyValuePair<string, object?>[] _metricTags;

    private ICancelable? _otpTimer = Cancelable.CreateCanceled();
    private ICancelable? _sessionTimer = Cancelable.CreateCanceled();
    private ICancelable? _cleanupFallbackTimer = Cancelable.CreateCanceled();
    private Option<VerificationFlowQueryRecord> _verificationFlow = Option<VerificationFlowQueryRecord>.None;
    private DateTimeOffset _sessionDeadline;
    private bool _sessionTimerPaused;

    private ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>>? _writer;
    private bool _isCompleting;
    private bool _timersStarted;
    private bool _cleanupCompleted;
    private CancellationTokenSource? _smsOperationCts;
    private OtpQueryRecord? _activeOtpRecord;
    private uint _lastPublishedRemainingSeconds;
    private bool _otpTimerStartLogged;
    private const int SnapshotInterval = 100;

#pragma warning disable CS0108
    public IStash Stash { get; set; } = null!;
#pragma warning restore CS0108

    public override string PersistenceId => $"verification-flow-{_connectId}";

    public VerificationFlowActor(
        uint connectId, Guid phoneNumberIdentifier, Guid appDeviceIdentifier, VerificationPurpose purpose,
        ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> writer,
        IActorRef persistor, IActorRef membershipActor, ISmsProvider smsProvider,
        ILocalizationProvider localizationProvider, string cultureName,
        IOptions<SecurityConfiguration> securityConfig,
        ActivityContext parentActivityContext,
        CancellationToken initialCancellationToken)
    {
        _connectId = connectId;
        _phoneNumberIdentifier = phoneNumberIdentifier;
        _writer = writer;
        _persistor = persistor;
        _membershipActor = membershipActor;
        _smsProvider = smsProvider;
        _localizationProvider = localizationProvider;
        _cultureName = cultureName;
        _timeouts = securityConfig.Value.VerificationFlow;
        _currentRequestCancellationToken = initialCancellationToken;
        _metricTags = new[] { KeyValuePair.Create<string, object?>("connectId", connectId) };
        ActivityContext parentContext = parentActivityContext != default
            ? parentActivityContext
            : Activity.Current?.Context ?? default;
        _activity = VerificationFlowTelemetry.ActivitySource.StartActivity(
            "verification.flow.session",
            ActivityKind.Internal,
            parentContext);
        _activity?.SetTag("verification.connect_id", connectId);
        _activity?.SetTag("verification.purpose", purpose.ToString());
        VerificationFlowTelemetry.ActiveFlows.Add(1, _metricTags);
        Serilog.Log.Information("[verification.flow.started] ConnectId {ConnectId} Purpose {Purpose}", _connectId, purpose);

        Recover<VerificationFlowActorSnapshot>(snapshot => ApplyPersistentState(snapshot.State));
        Recover<VerificationFlowStatePersistedEvent>(evt => ApplyPersistentState(evt.State));

        Become(WaitingForFlow);
        _persistor.Ask<Result<VerificationFlowQueryRecord, VerificationFlowFailure>>(
            new InitiateFlowAndReturnStateActorEvent(appDeviceIdentifier, _phoneNumberIdentifier, purpose, _connectId, initialCancellationToken)
        ).PipeTo(Self);
    }

    protected override void PreStart()
    {
        base.PreStart();
        Context.System.EventStream.Subscribe(Self, typeof(SessionExpiredMessageDeliveredEvent));
    }

    public static Props Build(
        uint connectId, Guid phoneNumberIdentifier, Guid appDeviceIdentifier, VerificationPurpose purpose,
        ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> writer,
        IActorRef persistor, IActorRef membershipActor, ISmsProvider smsProvider,
        ILocalizationProvider localizationProvider, string cultureName,
        IOptions<SecurityConfiguration> securityConfig,
        ActivityContext parentActivityContext,
        CancellationToken initialCancellationToken)
    {
        return Props.Create(() => new VerificationFlowActor(connectId, phoneNumberIdentifier, appDeviceIdentifier,
            purpose, writer, persistor, membershipActor, smsProvider, localizationProvider, cultureName, securityConfig,
            parentActivityContext,
            initialCancellationToken));
    }

    private void WaitingForFlow()
    {
        Command<RecoveryCompleted>(_ => HandleRecoveryCompleted());

        CommandAsync<Result<VerificationFlowQueryRecord, VerificationFlowFailure>>(async result =>
        {
            if (result.IsErr)
            {
                VerificationFlowFailure verificationFlowFailure = result.UnwrapErr();
                if (verificationFlowFailure is { IsUserFacing: true, IsSecurityRelated: true })
                {
                    string message = _localizationProvider.Localize(verificationFlowFailure.Message, _cultureName);

                    await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                        new VerificationCountdownUpdate
                        {
                            SecondsRemaining = 0,
                            SessionIdentifier = ByteString.Empty,
                            Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.Failed,
                            Message = message
                        }));
                }

                if (verificationFlowFailure.FailureType is VerificationFlowFailureType.NotFound
                    or VerificationFlowFailureType.InvalidOpaque)
                {
                    await CompleteWithError(verificationFlowFailure);
                }
                else
                {
                    CancelOtpTimer();
                    Become(OtpExpiredWaitingForSession);
                }

                return;
            }

            VerificationFlowQueryRecord currentFlow = result.Unwrap();
            _verificationFlow = Option<VerificationFlowQueryRecord>.Some(currentFlow);
            _activeOtpRecord = currentFlow.OtpActive;
            _sessionDeadline = DateTimeOffset.UtcNow.Add(_timeouts.SessionTimeout);
            _activity?.SetTag("verification.flow_id", currentFlow.UniqueIdentifier);
            _activity?.SetTag("verification.purpose", currentFlow.Purpose.ToString());

            Serilog.Log.Debug("[verification.flow.state.loaded] ConnectId {ConnectId} FlowId {FlowId} Status {Status}",
                _connectId, currentFlow.UniqueIdentifier, currentFlow.Status);

            if (currentFlow.Status == VerificationFlowStatus.Verified)
            {
                await NotifyAlreadyVerified();
                return;
            }

            if (currentFlow.OtpActive is null)
            {
                await ContinueWithOtp();
            }
            else
            {
                _activeOtp = OneTimePassword.FromExisting(currentFlow.OtpActive);
                Self.Tell(new StartOtpTimerEvent());
                Become(Running);
                Stash.UnstashAll();
                PersistState();
            }
        });

        CommandAny(_ => Stash.Stash());
    }

    private async Task ContinueWithOtp(CancellationToken requestCancellationToken = default)
    {
        _isCompleting = false;
        _smsOperationCts?.Cancel();
        _smsOperationCts?.Dispose();
        _smsOperationCts = new CancellationTokenSource();

        CancellationToken effectiveCancellation =
            requestCancellationToken.CanBeCanceled ? requestCancellationToken : GetOperationCancellationToken();

        using CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
            _smsOperationCts.Token,
            effectiveCancellation);

        Result<Unit, VerificationFlowFailure> otpResult = await PrepareAndSendOtp(_cultureName, linkedCts.Token);
        if (otpResult.IsErr)
        {
            VerificationFlowFailure failure = otpResult.UnwrapErr();

            if (failure.IsUserFacing)
            {
                string message = _localizationProvider.Localize(failure.Message, _cultureName);
                await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                    new VerificationCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionIdentifier = _verificationFlow.HasValue
                            ? Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier)
                            : ByteString.Empty,
                        Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.Failed,
                        Message = message
                    }));
            }

            if (failure.FailureType is VerificationFlowFailureType.NotFound or VerificationFlowFailureType.Generic)
            {
                await CompleteWithError(failure);
            }
            else
            {
                CancelOtpTimer();
                Become(OtpExpiredWaitingForSession);
                Stash.UnstashAll();
            }
        }
        else
        {
            _lastPublishedRemainingSeconds = 0;
            _otpTimerStartLogged = false;
            Become(Running);
            Stash.UnstashAll();
            Self.Tell(new StartOtpTimerEvent());
        }
    }

    private void Running()
    {
        Command<StartOtpTimerEvent>(_ => StartTimers());
        CommandAsync<VerificationCountdownUpdate>(HandleTimerTick);
        CommandAsync<VerificationFlowExpiredEvent>(HandleSessionExpired);
        CommandAsync<VerifyFlowActorEvent>(HandleVerifyOtp);
        CommandAsync<InitiateVerificationFlowActorEvent>(HandleInitiateVerificationRequest);
        CommandAsync<PrepareForTerminationMessage>(HandleClientDisconnection);
        CommandAsync<SessionExpiredMessageDeliveredEvent>(HandleSessionExpiredMessageDelivered);
        CommandAsync<FallbackCleanupEvent>(HandleFallbackCleanup);
    }

    private void OtpActive()
    {
        Command<StartOtpTimerEvent>(_ => { });
        CommandAsync<VerificationCountdownUpdate>(HandleTimerTick);
        CommandAsync<VerificationFlowExpiredEvent>(HandleSessionExpired);
        CommandAsync<VerifyFlowActorEvent>(HandleVerifyOtp);
        CommandAsync<InitiateVerificationFlowActorEvent>(HandleInitiateVerificationRequest);
        CommandAsync<PrepareForTerminationMessage>(HandleClientDisconnection);
        CommandAsync<SessionExpiredMessageDeliveredEvent>(HandleSessionExpiredMessageDelivered);
        CommandAsync<FallbackCleanupEvent>(HandleFallbackCleanup);
    }

    private void OtpExpiredWaitingForSession()
    {
        Command<StartOtpTimerEvent>(_ => { });
        CommandAsync<VerificationCountdownUpdate>(_ => Task.CompletedTask);
        CommandAsync<VerificationFlowExpiredEvent>(HandleSessionExpired);
        CommandAsync<VerifyFlowActorEvent>(actorEvent =>
        {
            string message =
                _localizationProvider.Localize(VerificationFlowMessageKeys.InvalidOtp, actorEvent.CultureName);
            Sender.Tell(CreateVerifyResponse(VerificationResult.Expired, message));
            return Task.CompletedTask;
        });
        CommandAsync<InitiateVerificationFlowActorEvent>(HandleInitiateVerificationRequest);
        CommandAsync<PrepareForTerminationMessage>(HandleClientDisconnection);
        CommandAsync<SessionExpiredMessageDeliveredEvent>(HandleSessionExpiredMessageDelivered);
        CommandAsync<FallbackCleanupEvent>(HandleFallbackCleanup);
    }

    private async Task HandleVerifyOtp(VerifyFlowActorEvent actorEvent)
    {
        try
        {
            if (_activeOtp?.IsActive != true)
            {
                Sender.Tell(CreateVerifyResponse(VerificationResult.Expired, VerificationFlowMessageKeys.InvalidOtp));
                return;
            }

            bool verificationSucceeded;
            try
            {
                verificationSucceeded = _activeOtp.Verify(actorEvent.OneTimePassword);
            }
            catch (Exception ex)
            {
                Serilog.Log.Error(ex, "[verification.otp.verify.failed] ConnectId {ConnectId}", _connectId);
                Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Generic("Failed to verify OTP due to system error")));
                return;
            }

            if (verificationSucceeded)
            {
                await HandleSuccessfulVerification();
            }
            else
            {
                await HandleFailedVerification(actorEvent.CultureName);
            }
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "[verification.otp.verify.unhandled] ConnectId {ConnectId}", _connectId);
            Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Failed to verify OTP due to system error")));
        }
    }

    private async Task HandleSuccessfulVerification()
    {
        _isCompleting = true;
        CancelTimers();
        _sessionTimerPaused = false;

        CompleteWriter();

        try
        {
            await UpdateOtpStatus(VerificationFlowStatus.Verified);

            if (_verificationFlow.HasValue)
            {
                await _persistor.Ask<Result<Unit, VerificationFlowFailure>>(
                    new UpdateVerificationFlowStatusActorEvent(_verificationFlow.Value!.UniqueIdentifier,
                        VerificationFlowStatus.Verified, GetOperationCancellationToken()),
                    _timeouts.UpdateOtpStatusTimeout);
            }
        }
        catch
        {
            Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Failed to verify OTP due to system error")));
            return;
        }

        if (!_verificationFlow.HasValue || _activeOtp == null)
        {

            Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Verification state is invalid")));
            return;
        }

        if (_verificationFlow.Value!.Purpose == VerificationPurpose.PasswordRecovery)
        {
            try
            {
                GetMembershipByVerificationFlowEvent getMembershipEvent = new(
                    _verificationFlow.Value!.UniqueIdentifier,
                    GetOperationCancellationToken());
                Result<MembershipQueryRecord, VerificationFlowFailure> result =
                    await _membershipActor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(
                        getMembershipEvent, _timeouts.MembershipCreationTimeout);

                result.Switch(
                    membership => { Sender.Tell(CreateSuccessResponse(membership)); },
                    failure => { Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(failure)); }
                );
            }
            catch
            {
                Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Generic("Failed to fetch membership for password recovery")));
            }

            ClearActiveOtpState();
            await TerminateActor(graceful: true, publishCleanupEvent: true, reason: "password_recovery_verified");
            return;
        }

        if (await HandleExistingMembershipAsync())
        {
            return;
        }

        CreateMembershipActorEvent createEvent = new(_connectId, _verificationFlow.Value!.UniqueIdentifier,
            _activeOtp.UniqueIdentifier, Membership.Types.CreationStatus.OtpVerified, GetOperationCancellationToken());

        try
        {
            Result<MembershipQueryRecord, VerificationFlowFailure> result =
                await _membershipActor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(
                    createEvent, _timeouts.MembershipCreationTimeout);

            result.Switch(
                membership => { Sender.Tell(CreateSuccessResponse(membership)); },
                failure => { Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(failure)); }
            );
        }
        catch
        {
            Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Failed to create membership due to system error")));
        }

        Serilog.Log.Information("[verification.otp.verified] ConnectId {ConnectId} FlowId {FlowId}",
            _connectId,
            _verificationFlow.Value.UniqueIdentifier);
        _activity?.AddEvent(new ActivityEvent("verification.otp.verified"));

        ClearActiveOtpState();
        await TerminateActor(graceful: true, publishCleanupEvent: true, reason: "otp_verified_new_membership");
    }

    private async Task HandleFailedVerification(string cultureName)
    {
        await UpdateOtpStatus(VerificationFlowStatus.Failed);
        VerificationFlowTelemetry.OtpFailed.Add(1, _metricTags);
        Serilog.Log.Warning("[verification.otp.failed] ConnectId {ConnectId} FlowId {FlowId} Reason invalid_otp",
            _connectId,
            _verificationFlow.HasValue ? _verificationFlow.Value!.UniqueIdentifier : Guid.Empty);
        _activity?.AddEvent(new ActivityEvent("verification.otp.failed"));

        string message = _localizationProvider.Localize(VerificationFlowMessageKeys.InvalidOtp, cultureName);

        Sender.Tell(CreateVerifyResponse(VerificationResult.InvalidOtp, message));
    }

    private async Task HandleInitiateVerificationRequest(InitiateVerificationFlowActorEvent actorEvent)
    {
        if (actorEvent.ConnectId != _connectId)
            return;

        if (actorEvent.CancellationToken.CanBeCanceled)
        {
            _currentRequestCancellationToken = actorEvent.CancellationToken;
        }

        if (actorEvent.RequestType == InitiateVerificationRequest.Types.Type.SendOtp)
        {
            _isCompleting = false;
            _timersStarted = false;
            CancelTimers();
            CompleteWriter();
            _writer = actorEvent.ChannelWriter;
            _writerCompleted = false;
            await ContinueWithOtp();
            Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
            return;
        }

        if (actorEvent.RequestType != InitiateVerificationRequest.Types.Type.ResendOtp)
        {
            return;
        }

        if (!_verificationFlow.HasValue)
        {

            await CompleteWithError(VerificationFlowFailure.Generic("Verification flow not initialized"));
            return;
        }

        Result<string, VerificationFlowFailure> checkResult =
            await _persistor.Ask<Result<string, VerificationFlowFailure>>(
                new RequestResendOtpActorEvent(_verificationFlow.Value!.UniqueIdentifier, actorEvent.CancellationToken),
                _timeouts.ResendOtpCheckTimeout);
        if (checkResult.IsErr)
        {
            VerificationFlowFailure failure = checkResult.UnwrapErr();

            if (failure.IsUserFacing)
            {
                string message = _localizationProvider.Localize(failure.Message, _cultureName);
                await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                    new VerificationCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                        Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.Failed,
                        Message = message
                    }));
            }

            Sender.Tell(Result<Unit, VerificationFlowFailure>.Err(failure));
            return;
        }

        string outcome = checkResult.Unwrap();
        switch (outcome)
        {
            case VerificationFlowMessageKeys.ResendAllowed:
                _timersStarted = false;
                CancelTimers();
                CompleteWriter();
                _writer = actorEvent.ChannelWriter;
                _writerCompleted = false;
                _sessionDeadline = DateTimeOffset.UtcNow.Add(_timeouts.SessionTimeout);
                await ContinueWithOtp(actorEvent.CancellationToken);
                break;
            case VerificationFlowMessageKeys.OtpMaxAttemptsReached:
                await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                    new VerificationCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value.UniqueIdentifier),
                        Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.MaxAttemptsReached,
                        Message = _localizationProvider.Localize(VerificationFlowMessageKeys.OtpMaxAttemptsReached,
                            actorEvent.CultureName)
                    }));
                break;
            case VerificationFlowMessageKeys.ResendCooldown:
                await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                    new VerificationCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value.UniqueIdentifier),
                        Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.Failed,
                        Message = _localizationProvider.Localize(VerificationFlowMessageKeys.ResendCooldown)
                    }));
                break;
            default:
                await CompleteWithError(
                    VerificationFlowFailure.Generic($"Unknown outcome from RequestResendOtp: {outcome}"));
                break;
        }

        Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
    }

    private void StartTimers()
    {
        if (_isCompleting)
        {
            return;
        }

        if (_timersStarted &&
            _activeOtp?.IsActive == true &&
            _otpTimer is { IsCancellationRequested: false })
        {
            return;
        }

        if (!_verificationFlow.HasValue)
        {
            Serilog.Log.Debug("[verification.timers.skipped] No verification flow state present for ConnectId {ConnectId}",
                _connectId);
            return;
        }

        bool sessionTimerNotStarted = !_timersStarted;

        CancelOtpTimer();

        if (sessionTimerNotStarted)
        {
            StartSessionTimer();
        }

        StartOtpTimer();
    }

    private void StartSessionTimer()
    {
        if (!_verificationFlow.HasValue)
            return;

        TimeSpan sessionDelay = _sessionDeadline - DateTimeOffset.UtcNow;
        if (sessionDelay > TimeSpan.Zero)
        {
            _sessionTimer = Context.System.Scheduler.ScheduleTellOnceCancelable(sessionDelay, Self,
                new VerificationFlowExpiredEvent(_cultureName), ActorRefs.NoSender);
        }
    }

    private void StartOtpTimer()
    {
        CancelOtpTimer();

        if (_activeOtp?.IsActive != true)
        {
            Serilog.Log.Debug("[verification.timers.skipped] Attempted to start OTP timer without active OTP for ConnectId {ConnectId}",
                _connectId);
            return;
        }

        _activeOtpRemainingSeconds = CalculateRemainingSeconds(_activeOtp.ExpiresAt);

        if (_activeOtpRemainingSeconds > 0)
        {
            _timersStarted = true;
            _otpTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(TimeSpan.Zero,
                _timeouts.OtpUpdateInterval, Self, new VerificationCountdownUpdate(), ActorRefs.NoSender);

            PauseSessionTimer();
            Become(OtpActive);

            if (!_otpTimerStartLogged)
            {
                Serilog.Log.Information("[verification.otp.timer-started] ConnectId {ConnectId} FlowId {FlowId} ExpiresAt {ExpiresAt}",
                    _connectId,
                    _verificationFlow.HasValue ? _verificationFlow.Value!.UniqueIdentifier : Guid.Empty,
                    _activeOtp.ExpiresAt);
                _otpTimerStartLogged = true;
            }

            Self.Tell(new VerificationCountdownUpdate());
        }
        else
        {
            _timersStarted = false;
        }
    }

    private void CancelOtpTimer()
    {
        if (_otpTimer?.IsCancellationRequested == false)
        {
            _otpTimer.Cancel(true);
            _otpTimer = null;
        }
    }

    private async Task HandleTimerTick(VerificationCountdownUpdate _)
    {
        if (_isCompleting || _cleanupCompleted || _otpTimer is null || _otpTimer.IsCancellationRequested)
        {
            return;
        }

        if (_activeOtp?.IsActive != true)
        {
            await ExpireCurrentOtp();
            return;
        }

        uint actualRemaining = CalculateRemainingSeconds(_activeOtp.ExpiresAt);

        _activeOtpRemainingSeconds = actualRemaining;

        if (_activeOtpRemainingSeconds <= 0)
        {
            if (_verificationFlow.HasValue)
            {
                await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                    new VerificationCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                        Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.Expired
                    }));
                Serilog.Log.Information("[verification.otp.countdown] ConnectId {ConnectId} FlowId {FlowId} Remaining {Remaining}",
                    _connectId, _verificationFlow.Value!.UniqueIdentifier, 0);
                _lastPublishedRemainingSeconds = 0;
            }

            await ExpireCurrentOtp();
            Become(OtpExpiredWaitingForSession);
            return;
        }

        if (_verificationFlow.HasValue)
        {
            if (_lastPublishedRemainingSeconds != _activeOtpRemainingSeconds)
            {
                Serilog.Log.Information("[verification.otp.countdown] ConnectId {ConnectId} FlowId {FlowId} Remaining {Remaining}",
                    _connectId, _verificationFlow.Value!.UniqueIdentifier, _activeOtpRemainingSeconds);
                _lastPublishedRemainingSeconds = _activeOtpRemainingSeconds;
            }

            await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                new VerificationCountdownUpdate
                {
                    SecondsRemaining = _activeOtpRemainingSeconds,
                    SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                    Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.Active
                }));
        }
    }

    private async Task HandleSessionExpired(VerificationFlowExpiredEvent actorEvent)
    {
        if (_sessionTimerPaused || _cleanupCompleted)
            return;

        CancelTimers();
        _sessionTimerPaused = false;

        if (_activeOtp != null)
        {
            await UpdateOtpStatus(VerificationFlowStatus.Expired);

            _activeOtp = null;
        }

        if (_verificationFlow.HasValue)
        {
            await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                new VerificationCountdownUpdate
                {
                    SecondsRemaining = 0,
                    SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                    Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.SessionExpired,
                    Message = _localizationProvider.Localize(VerificationFlowMessageKeys.VerificationFlowExpired,
                        actorEvent.CultureName)
                }));
        }

        _isCompleting = true;

        _cleanupFallbackTimer = Context.System.Scheduler.ScheduleTellOnceCancelable(
            _timeouts.FallbackCleanupDelay, Self, new FallbackCleanupEvent(), ActorRefs.NoSender);

        PersistState();
    }

    private async Task HandleFallbackCleanup(FallbackCleanupEvent _)
    {
        await PerformCleanup();
    }

    private async Task HandleSessionExpiredMessageDelivered(SessionExpiredMessageDeliveredEvent evt)
    {
        if (evt.ConnectId != _connectId)
            return;

        if (_cleanupFallbackTimer?.IsCancellationRequested == false)
        {
            _cleanupFallbackTimer.Cancel(false);
        }

        await PerformCleanup();
    }

    private async Task PerformCleanup()
    {
        await TerminateActor(graceful: true, updateFlowToExpired: true, reason: "fallback_cleanup");
    }

    private async Task HandleClientDisconnection(PrepareForTerminationMessage _)
    {
        _isCompleting = true;
        IActorRef replyTo = Sender;
        CompleteWriter();

        if (_activeOtp?.IsActive == true)
        {
            await UpdateOtpStatus(VerificationFlowStatus.Expired);
        }

        await TerminateActor(graceful: true, updateFlowToExpired: true, reason: "client_disconnect");

        if (!replyTo.IsNobody())
        {
            replyTo.Tell(FlowTerminationAcknowledged.Instance);
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> PrepareAndSendOtp(string cultureName, CancellationToken cancellationToken = default)
    {
        GetMobileNumberActorEvent getMobileNumberActorEvent = new(_phoneNumberIdentifier, cancellationToken);

        Result<MobileNumberQueryRecord, VerificationFlowFailure> phoneNumberQueryRecordResult =
            await _persistor.Ask<Result<MobileNumberQueryRecord, VerificationFlowFailure>>(getMobileNumberActorEvent);

        if (phoneNumberQueryRecordResult.IsErr)
            return Result<Unit, VerificationFlowFailure>.Err(phoneNumberQueryRecordResult.UnwrapErr());

        MobileNumberQueryRecord phoneNumberQueryRecord = phoneNumberQueryRecordResult.Unwrap();

        if (!_verificationFlow.HasValue)
        {
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Verification flow not initialized"));
        }

        OneTimePassword otp = new(_timeouts.OtpExpiration);
        otp.UniqueIdentifier = Guid.NewGuid();
        Result<(OtpQueryRecord Record, string PlainOtp), VerificationFlowFailure> generationResult =
            otp.Generate(phoneNumberQueryRecord, _verificationFlow.Value!.UniqueIdentifier);
        if (generationResult.IsErr) return Result<Unit, VerificationFlowFailure>.Err(generationResult.UnwrapErr());

        (OtpQueryRecord otpRecord, string plainOtp) = generationResult.Unwrap();
        otpRecord = otpRecord with { UniqueIdentifier = otp.UniqueIdentifier };

        Result<CreateOtpResult, VerificationFlowFailure> createResult =
            await _persistor.Ask<Result<CreateOtpResult, VerificationFlowFailure>>(
                new CreateOtpActorEvent(otpRecord, cancellationToken),
                _timeouts.CreateOtpTimeout);

        if (createResult.IsErr) return Result<Unit, VerificationFlowFailure>.Err(createResult.UnwrapErr());

        CreateOtpResult createOtp = createResult.Unwrap();

        _activeOtp = otp;
        _activeOtp.UniqueIdentifier = createOtp.OtpUniqueId;
        _activeOtpRecord = otpRecord with { UniqueIdentifier = createOtp.OtpUniqueId };

        if (_verificationFlow.HasValue)
        {
            _verificationFlow = Option<VerificationFlowQueryRecord>.Some(_verificationFlow.Value with
            {
                OtpCount = _verificationFlow.Value.OtpCount + 1
            });
        }

        string localizedString =
            _localizationProvider.Localize(VerificationFlowMessageKeys.AuthenticationCodeIs, cultureName);
        StringBuilder messageBuilder = new(localizedString + ": " + plainOtp);

        int smsAttempt = 0;
        SmsDeliveryResult? smsResult = null;
        Stopwatch smsStopwatch = Stopwatch.StartNew();
        _otpSendAttempts++;

        try
        {
            while (smsAttempt < _timeouts.MaxSmsRetries)
            {
                smsAttempt++;
                smsResult = await _smsProvider.SendOtpAsync(phoneNumberQueryRecord.MobileNumber, messageBuilder.ToString(), cancellationToken);

                if (smsResult.IsSuccess)
                {
                    break;
                }

                if (smsAttempt >= _timeouts.MaxSmsRetries) continue;
                int delayMs = (int)Math.Pow(2, smsAttempt - 1) * 1000;
                await Task.Delay(delayMs, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            VerificationFlowTelemetry.OtpFailed.Add(1, _metricTags);
            Serilog.Log.Debug("SMS retry operation was cancelled for phone number ending in {PhoneNumberSuffix}",
                phoneNumberQueryRecord.MobileNumber.Length > 4
                    ? phoneNumberQueryRecord.MobileNumber[^4..]
                    : "****");

            _activeOtp = null;
            _activeOtpRecord = null;

            PersistState();

            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("SMS operation was cancelled"));
        }

        if (smsResult?.IsSuccess != true)
        {
            try
            {
                await UpdateOtpStatus(VerificationFlowStatus.Failed);
            }
            catch
            {
            }

            VerificationFlowTelemetry.OtpFailed.Add(1, _metricTags);
            Serilog.Log.Warning("[verification.otp.failed] ConnectId {ConnectId} FlowId {FlowId} Attempts {Attempts} Error {Error}",
                _connectId,
                _verificationFlow.Value?.UniqueIdentifier,
                smsAttempt,
                smsResult?.ErrorMessage ?? "unknown");
            _activity?.AddEvent(new ActivityEvent("verification.otp.failed"));

            _activeOtp = null;
            _activeOtpRecord = null;

            PersistState();

            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.SmsSendFailed(
                    $"Failed to send SMS after {_timeouts.MaxSmsRetries} attempts: {smsResult?.ErrorMessage}"));
        }

        smsStopwatch.Stop();
        VerificationFlowTelemetry.OtpSent.Add(1, _metricTags);
        VerificationFlowTelemetry.OtpSendLatency.Record(smsStopwatch.Elapsed.TotalMilliseconds, _metricTags);
        Serilog.Log.Information("[verification.otp.sent] ConnectId {ConnectId} FlowId {FlowId} Attempts {Attempts}",
            _connectId,
            _verificationFlow.Value?.UniqueIdentifier,
            smsAttempt);
        _activity?.AddEvent(new ActivityEvent("verification.otp.sent"));

        PersistState();

        return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
    }

    private async Task<bool> HandleExistingMembershipAsync()
    {
        try
        {
            CheckExistingMembershipActorEvent checkMembershipEvent = new(
                _phoneNumberIdentifier, GetOperationCancellationToken());

            Result<ExistingMembershipResult, VerificationFlowFailure> membershipResult =
                await _persistor.Ask<Result<ExistingMembershipResult, VerificationFlowFailure>>(
                    checkMembershipEvent, _timeouts.MembershipCreationTimeout);

            if (membershipResult.IsErr)
            {
                Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(membershipResult.UnwrapErr()));
                ClearActiveOtpState();
                await TerminateActor(graceful: true, publishCleanupEvent: true, reason: "existing_membership_error");
                return true;
            }

            ExistingMembershipResult existingMembership = membershipResult.Unwrap();

            if (existingMembership is { MembershipExists: true, Membership: not null })
            {
                Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Ok(new VerifyCodeResponse
                {
                    Result = VerificationResult.Succeeded,
                    Membership = existingMembership.Membership
                }));

                ClearActiveOtpState();
                await TerminateActor(graceful: true, publishCleanupEvent: true, reason: "otp_verified_existing_membership");
                return true;
            }
        }
        catch
        {
            Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Failed to check existing membership")));
            ClearActiveOtpState();
            await TerminateActor(graceful: true, publishCleanupEvent: true, reason: "existing_membership_check_failed");
            return true;
        }

        return false;
    }

    private VerificationFlowPersistentState CapturePersistentState()
    {
        return new VerificationFlowPersistentState(
            _verificationFlow.Match<VerificationFlowQueryRecord?>(v => v, () => null),
            _activeOtpRecord,
            _sessionDeadline == default ? null : _sessionDeadline,
            _sessionTimerPaused,
            _otpSendAttempts,
            _cleanupCompleted,
            _isCompleting,
            _timersStarted);
    }

    private void ApplyPersistentState(VerificationFlowPersistentState state)
    {
        _verificationFlow = state.VerificationFlow != null
            ? Option<VerificationFlowQueryRecord>.Some(state.VerificationFlow)
            : Option<VerificationFlowQueryRecord>.None;

        _activeOtpRecord = state.ActiveOtp;
        _activeOtp = state.ActiveOtp != null ? OneTimePassword.FromExisting(state.ActiveOtp) : null;
        _sessionDeadline = state.SessionDeadline ?? default;
        _sessionTimerPaused = state.SessionTimerPaused;
        _otpSendAttempts = state.OtpSendAttempts;
        _cleanupCompleted = state.CleanupCompleted;
        _isCompleting = state.IsCompleting;
        _timersStarted = state.TimersStarted;
        _activeOtpRemainingSeconds = _activeOtp != null
            ? CalculateRemainingSeconds(_activeOtp.ExpiresAt)
            : 0;
    }

    private void PersistState(Action? afterApply = null)
    {
        VerificationFlowPersistentState snapshot = CapturePersistentState();
        PersistAsync(new VerificationFlowStatePersistedEvent(snapshot), evt =>
        {
            MaybeSaveSnapshot();
            afterApply?.Invoke();
        });
    }

    private void MaybeSaveSnapshot()
    {
        if (LastSequenceNr == 0 || LastSequenceNr % SnapshotInterval != 0)
        {
            return;
        }

        SaveSnapshot(new VerificationFlowActorSnapshot(CapturePersistentState()));
    }

    private async Task NotifyAlreadyVerified()
    {
        if (_verificationFlow.HasValue)
        {
            await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                new VerificationCountdownUpdate
                {
                    SecondsRemaining = 0,
                    SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                    AlreadyVerified = true
                }));
        }

        await TerminateActor(graceful: false, publishCleanupEvent: false);
    }

    private void HandleRecoveryCompleted()
    {
        if (_verificationFlow.HasValue && _sessionDeadline == default)
        {
            _sessionDeadline = DateTimeOffset.UtcNow.Add(_timeouts.SessionTimeout);
        }

        if (_activeOtp is { IsActive: true })
        {
            _timersStarted = false;
            Self.Tell(new StartOtpTimerEvent());
        }
    }

    private async Task ExpireCurrentOtp()
    {
        if (_activeOtp != null)
        {
            await UpdateOtpStatus(VerificationFlowStatus.Expired);
            _activeOtp = null;
            _activeOtpRecord = null;
        }

        CancelOtpTimer();
        ResumeSessionTimer();
        PersistState();
    }

    private void ClearActiveOtpState()
    {
        _activeOtp = null;
        _activeOtpRecord = null;
        _otpTimerStartLogged = false;
        _lastPublishedRemainingSeconds = 0;
    }

    private CancellationToken GetOperationCancellationToken()
    {
        return _currentRequestCancellationToken.IsCancellationRequested
            ? CancellationToken.None
            : _currentRequestCancellationToken;
    }

    private async Task UpdateOtpStatus(VerificationFlowStatus status)
    {
        if (_activeOtp == null)
        {
            return;
        }

        try
        {
            Result<Unit, VerificationFlowFailure> result =
                await _persistor.Ask<Result<Unit, VerificationFlowFailure>>(
                    new UpdateOtpStatusActorEvent(_activeOtp.UniqueIdentifier, status, GetOperationCancellationToken()),
                    _timeouts.UpdateOtpStatusTimeout);

            if (result.IsErr)
            {
                VerificationFlowFailure failure = result.UnwrapErr();
                Serilog.Log.Warning("[verification.otp.status-update-warning] ConnectId {ConnectId} Status {Status} Failure {Failure}",
                    _connectId, status, failure.Message);
            }
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "[verification.otp.status-update-failed] ConnectId {ConnectId} Status {Status}",
                _connectId, status);
        }
    }

    private static uint CalculateRemainingSeconds(DateTimeOffset expiresAt)
    {
        return (uint)Math.Max(0, Math.Ceiling((expiresAt - DateTimeOffset.UtcNow).TotalSeconds));
    }

    private static Result<VerifyCodeResponse, VerificationFlowFailure> CreateVerifyResponse(VerificationResult result,
        string message)
    {
        return Result<VerifyCodeResponse, VerificationFlowFailure>.Ok(new VerifyCodeResponse
        { Result = result, Message = message });
    }

    private static Result<VerifyCodeResponse, VerificationFlowFailure>
        CreateSuccessResponse(MembershipQueryRecord membership)
    {
        return Result<VerifyCodeResponse, VerificationFlowFailure>.Ok(new VerifyCodeResponse
        {
            Result = VerificationResult.Succeeded,
            Membership = new Membership
            {
                UniqueIdentifier = Helpers.GuidToByteString(membership.UniqueIdentifier),
                Status = membership.ActivityStatus,
                CreationStatus = membership.CreationStatus
            }
        });
    }

    private async Task TerminateActor(
        bool graceful = true,
        bool updateFlowToExpired = false,
        Exception? error = null,
        bool publishCleanupEvent = true,
        string reason = "unspecified")
    {
        if (_cleanupCompleted)
            return;

        _cleanupCompleted = true;

        CancelTimers();
        _sessionTimerPaused = false;

        if (updateFlowToExpired && _verificationFlow.HasValue)
        {
            try
            {
            Result<Unit, VerificationFlowFailure> result =
                await _persistor.Ask<Result<Unit, VerificationFlowFailure>>(
                    new UpdateVerificationFlowStatusActorEvent(_verificationFlow.Value!.UniqueIdentifier,
                        VerificationFlowStatus.Expired, GetOperationCancellationToken()));

                if (result.IsErr)
                {
                    VerificationFlowFailure failure = result.UnwrapErr();
                    Serilog.Log.Warning("[verification.flow.expire-warning] ConnectId {ConnectId} FlowId {FlowId} Failure {Failure}",
                        _connectId, _verificationFlow.Value!.UniqueIdentifier, failure.Message);
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Error(ex, "[verification.flow.expire-failed] ConnectId {ConnectId} FlowId {FlowId}",
                    _connectId, _verificationFlow.Value!.UniqueIdentifier);
            }
        }

        CompleteWriter(error);

        Serilog.Log.Information("[verification.flow.terminated] ConnectId {ConnectId} FlowId {FlowId} Graceful {Graceful} Reason {Reason}",
            _connectId,
            _verificationFlow.HasValue ? _verificationFlow.Value!.UniqueIdentifier : Guid.Empty,
            graceful,
            reason);

        if (publishCleanupEvent)
        {

            Context.System.EventStream.Publish(new ProtocolCleanupRequiredEvent(_connectId));
        }

        if (graceful)
        {
            Context.Parent.Tell(new FlowCompletedGracefullyActorEvent(Self));
        }

        _activity?.AddEvent(new ActivityEvent("verification.flow.terminated"));

        Self.Tell(PoisonPill.Instance);
    }

    private async Task CompleteWithError(VerificationFlowFailure failure)
    {
        bool isGraceful = failure.IsUserFacing;

        await TerminateActor(
            graceful: isGraceful,
            error: failure.InnerException,
            publishCleanupEvent: false,
            reason: $"failure_{failure.FailureType}");
    }

    private void CancelTimers()
    {
        try
        {
            CancelOtpTimer();

            if (_sessionTimer?.IsCancellationRequested == false)
            {
                _sessionTimer.Cancel(true);
                _sessionTimer = null;
            }

            if (_cleanupFallbackTimer?.IsCancellationRequested == false)
            {
                _cleanupFallbackTimer.Cancel(true);
                _cleanupFallbackTimer = null;
            }

            if (_smsOperationCts is { IsCancellationRequested: false })
            {
                _smsOperationCts.Cancel();
            }

            _timersStarted = false;
            _sessionTimerPaused = false;
        }
        catch (Exception ex)
        {
            Serilog.Log.Debug(ex, "[verification.flow.cancel-timers-warning] ConnectId {ConnectId}", _connectId);
        }
    }

    private void CompleteWriter(Exception? error = null)
    {
        if (_writerCompleted)
        {
            return;
        }

        ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>>? writer =
            Interlocked.Exchange(ref _writer, null);

        _writerCompleted = true;

        if (writer == null)
        {
            return;
        }

        try
        {
            if (error != null)
            {
                writer.TryComplete(error);
            }
            else
            {
                writer.TryComplete();
            }
        }
        catch (Exception ex)
        {
            Serilog.Log.Debug(ex, "[verification.channel.complete-warning] ConnectId {ConnectId}", _connectId);
        }
    }

    private void PauseSessionTimer()
    {
        if (_sessionTimer is { IsCancellationRequested: false })
        {
            _sessionTimer.Cancel(false);
            _sessionTimerPaused = true;
        }
    }

    private void ResumeSessionTimer()
    {
        if (!_sessionTimerPaused || _isCompleting || !_verificationFlow.HasValue)
            return;

        TimeSpan remaining = _sessionDeadline - DateTimeOffset.UtcNow;
        if (remaining > TimeSpan.Zero)
        {
            _sessionTimer = Context.System.Scheduler.ScheduleTellOnceCancelable(remaining, Self,
                new VerificationFlowExpiredEvent(_cultureName), ActorRefs.NoSender);
        }

        _sessionTimerPaused = false;
    }

    private async Task SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure> update)
    {
        ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>>? writer = _writer;
        if (writer == null)
        {
            return;
        }

        try
        {
            using CancellationTokenSource timeoutCts =
                CancellationTokenSource.CreateLinkedTokenSource(_currentRequestCancellationToken);
            timeoutCts.CancelAfter(_timeouts.ChannelWriteTimeout);
            await writer.WriteAsync(update, timeoutCts.Token);
        }
        catch (InvalidOperationException)
        {
            VerificationFlowTelemetry.ChannelDrops.Add(1, _metricTags);
            Serilog.Log.Warning("[verification.channel.drop] Channel closed while writing update for ConnectId {ConnectId}",
                _connectId);
            CompleteWriter();
        }
        catch (OperationCanceledException)
        {
            VerificationFlowTelemetry.ChannelDrops.Add(1, _metricTags);
            Serilog.Log.Warning("[verification.channel.drop] Write cancelled for ConnectId {ConnectId}", _connectId);
            if (!_currentRequestCancellationToken.IsCancellationRequested)
            {
                CompleteWriter();
            }
        }
        catch
        {
            VerificationFlowTelemetry.ChannelDrops.Add(1, _metricTags);
            CompleteWriter();
        }
    }

    protected override void PostStop()
    {
        try
        {
            CancelTimers();
            CompleteWriter();
            _smsOperationCts?.Dispose();
            _smsOperationCts = null;
            _activity?.Dispose();
            VerificationFlowTelemetry.ActiveFlows.Add(-1, _metricTags);
        }
        finally
        {
            base.PostStop();
        }
    }
}
