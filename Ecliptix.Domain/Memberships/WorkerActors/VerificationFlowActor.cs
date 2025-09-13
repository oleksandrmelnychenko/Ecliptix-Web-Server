using System.Text;
using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Providers.Twilio;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Google.Protobuf;
using Serilog;

namespace Ecliptix.Domain.Memberships.WorkerActors;

public record ProtocolCleanupRequiredEvent(uint ConnectId);

public record SessionExpiredMessageDeliveredEvent(uint ConnectId);

public record FallbackCleanupEvent();

public class VerificationFlowActor : ReceiveActor, IWithStash
{
    private readonly uint _connectId;
    private readonly string _cultureName;
    private readonly ILocalizationProvider _localizationProvider;
    private readonly IActorRef _membershipActor;
    private readonly IActorRef _persistor;
    private readonly Guid _phoneNumberIdentifier;
    private readonly ISmsProvider _smsProvider;
    private OneTimePassword? _activeOtp;
    private uint _activeOtpRemainingSeconds;

    private ICancelable? _otpTimer = Cancelable.CreateCanceled();
    private ICancelable? _sessionTimer = Cancelable.CreateCanceled();
    private ICancelable? _cleanupFallbackTimer = Cancelable.CreateCanceled();
    private Option<VerificationFlowQueryRecord> _verificationFlow = Option<VerificationFlowQueryRecord>.None;
    private DateTime _sessionDeadline;
    private bool _sessionTimerPaused;
    private TimeSpan _sessionRemainingTime;

    private ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> _writer;
    private bool _isCompleting;
    private bool _timersStarted;
    private bool _cleanupCompleted;

    public IStash Stash { get; set; } = null!;

    public VerificationFlowActor(
        uint connectId, Guid phoneNumberIdentifier, Guid appDeviceIdentifier, VerificationPurpose purpose,
        ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> writer,
        IActorRef persistor, IActorRef membershipActor, ISmsProvider smsProvider,
        ILocalizationProvider localizationProvider, string cultureName)
    {
        _connectId = connectId;
        _phoneNumberIdentifier = phoneNumberIdentifier;
        _writer = writer;
        _persistor = persistor;
        _membershipActor = membershipActor;
        _smsProvider = smsProvider;
        _localizationProvider = localizationProvider;
        _cultureName = cultureName;

        Become(WaitingForFlow);
        _persistor.Ask<Result<VerificationFlowQueryRecord, VerificationFlowFailure>>(
            new InitiateFlowAndReturnStateActorEvent(appDeviceIdentifier, _phoneNumberIdentifier, purpose, _connectId)
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
        ILocalizationProvider localizationProvider, string cultureName)
    {
        return Props.Create(() => new VerificationFlowActor(connectId, phoneNumberIdentifier, appDeviceIdentifier,
            purpose, writer, persistor, membershipActor, smsProvider, localizationProvider, cultureName));
    }

    private void WaitingForFlow()
    {
        ReceiveAsync<Result<VerificationFlowQueryRecord, VerificationFlowFailure>>(async result =>
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
                else
                {
                    await CompleteWithError(result.UnwrapErr());
                }

                return;
            }

            VerificationFlowQueryRecord currentFlow = result.Unwrap();
            _verificationFlow = Option<VerificationFlowQueryRecord>.Some(currentFlow);
            _sessionDeadline = currentFlow.ExpiresAt;
            _sessionRemainingTime = _sessionDeadline - DateTime.UtcNow;

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
            }
        });

        ReceiveAny(_ => Stash.Stash());
    }

    private async Task ContinueWithOtp()
    {
        Result<Unit, VerificationFlowFailure> otpResult = await PrepareAndSendOtp(_cultureName);
        otpResult.Switch(
            _ =>
            {
                Become(Running);
                Stash.UnstashAll();
                Self.Tell(new StartOtpTimerEvent());
            },
            async failure => await CompleteWithError(failure)
        );
    }

    private void Running()
    {
        Receive<StartOtpTimerEvent>(_ => StartTimers());
        ReceiveAsync<VerificationCountdownUpdate>(HandleTimerTick);
        ReceiveAsync<VerificationFlowExpiredEvent>(HandleSessionExpired);
        ReceiveAsync<VerifyFlowActorEvent>(HandleVerifyOtp);
        ReceiveAsync<InitiateVerificationFlowActorEvent>(HandleInitiateVerificationRequest);
        ReceiveAsync<PrepareForTerminationMessage>(HandleClientDisconnection);
        ReceiveAsync<SessionExpiredMessageDeliveredEvent>(HandleSessionExpiredMessageDelivered);
        ReceiveAsync<FallbackCleanupEvent>(HandleFallbackCleanup);
    }

    private void OtpActive()
    {
        Receive<StartOtpTimerEvent>(_ => { });
        ReceiveAsync<VerificationCountdownUpdate>(HandleTimerTick);
        ReceiveAsync<VerificationFlowExpiredEvent>(HandleSessionExpired);
        ReceiveAsync<VerifyFlowActorEvent>(HandleVerifyOtp);
        ReceiveAsync<InitiateVerificationFlowActorEvent>(HandleInitiateVerificationRequest);
        ReceiveAsync<PrepareForTerminationMessage>(HandleClientDisconnection);
        ReceiveAsync<SessionExpiredMessageDeliveredEvent>(HandleSessionExpiredMessageDelivered);
        ReceiveAsync<FallbackCleanupEvent>(HandleFallbackCleanup);
    }

    private void OtpExpiredWaitingForSession()
    {
        Receive<StartOtpTimerEvent>(_ => { });
        ReceiveAsync<VerificationCountdownUpdate>(_ => Task.CompletedTask);
        ReceiveAsync<VerificationFlowExpiredEvent>(HandleSessionExpired);
        ReceiveAsync<VerifyFlowActorEvent>(actorEvent =>
        {
            string message =
                _localizationProvider.Localize(VerificationFlowMessageKeys.InvalidOtp, actorEvent.CultureName);
            Sender.Tell(CreateVerifyResponse(VerificationResult.Expired, message));
            return Task.CompletedTask;
        });
        ReceiveAsync<InitiateVerificationFlowActorEvent>(HandleInitiateVerificationRequest);
        ReceiveAsync<PrepareForTerminationMessage>(HandleClientDisconnection);
        ReceiveAsync<SessionExpiredMessageDeliveredEvent>(HandleSessionExpiredMessageDelivered);
        ReceiveAsync<FallbackCleanupEvent>(HandleFallbackCleanup);
    }

    private async Task HandleVerifyOtp(VerifyFlowActorEvent actorEvent)
    {
        if (_activeOtp?.IsActive != true)
        {
            Sender.Tell(CreateVerifyResponse(VerificationResult.Expired, VerificationFlowMessageKeys.InvalidOtp));
            return;
        }

        if (_activeOtp.Verify(actorEvent.OneTimePassword))
        {
            Become(Running);
            await HandleSuccessfulVerification();
        }
        else
        {
            await HandleFailedVerification(actorEvent.CultureName);
        }
    }

    private async Task HandleSuccessfulVerification()
    {
        _isCompleting = true;
        CancelTimers();
        _sessionTimerPaused = false;

        try
        {
            _writer?.TryComplete();
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Error completing channel for ConnectId {ConnectId}", _connectId);
        }

        const int maxRetries = 3;
        bool otpUpdated = false;

        for (int attempt = 1; attempt <= maxRetries && !otpUpdated; attempt++)
        {
            try
            {
                await UpdateOtpStatus(VerificationFlowStatus.Verified);
                otpUpdated = true;
            }
            catch (Exception ex)
            {
                Log.Warning(ex,
                    "Failed to update OTP status on attempt {Attempt}/{MaxAttempts} for ConnectId {ConnectId}",
                    attempt, maxRetries, _connectId);

                if (attempt < maxRetries)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(100 * attempt));
                }
            }
        }

        if (!otpUpdated)
        {
            Log.Error("Failed to update OTP status after {MaxRetries} attempts for ConnectId {ConnectId}", maxRetries, _connectId);
            Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Failed to verify OTP due to system error")));
            return;
        }

        if (!_verificationFlow.HasValue || _activeOtp == null)
        {
            Log.Error("Cannot create membership: verification flow or OTP is null for ConnectId {ConnectId}", _connectId);
            Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Verification state is invalid")));
            return;
        }

        CreateMembershipActorEvent createEvent = new(_connectId, _verificationFlow.Value.UniqueIdentifier,
            _activeOtp.UniqueIdentifier, Membership.Types.CreationStatus.OtpVerified);

        try
        {
            Result<MembershipQueryRecord, VerificationFlowFailure> result =
                await _membershipActor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(
                    createEvent, TimeSpan.FromSeconds(10));

            result.Switch(
                membership => { Sender.Tell(CreateSuccessResponse(membership)); },
                failure =>
                {
                    Log.Error("Failed to create membership for ConnectId {ConnectId}: {Error}",
                        _connectId, failure.Message);
                    Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(failure));
                }
            );
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Unexpected error creating membership for ConnectId {ConnectId}", _connectId);
            Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Failed to create membership due to system error")));
        }

        await TerminateActor(graceful: true, publishCleanupEvent: false);
    }

    private async Task HandleFailedVerification(string cultureName)
    {
        await UpdateOtpStatus(VerificationFlowStatus.Failed);

        string message = _localizationProvider.Localize(VerificationFlowMessageKeys.InvalidOtp, cultureName);

        Sender.Tell(CreateVerifyResponse(VerificationResult.InvalidOtp, message));
    }

    private async Task HandleInitiateVerificationRequest(InitiateVerificationFlowActorEvent actorEvent)
    {
        if (actorEvent.ConnectId != _connectId)
            return;

        if (actorEvent.RequestType == InitiateVerificationRequest.Types.Type.SendOtp)
        {
            _isCompleting = false;
            _timersStarted = false;
            CancelTimers();
            _writer?.TryComplete();
            _writer = actorEvent.ChannelWriter;
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
            Log.Error("Cannot process resend OTP: verification flow is null for ConnectId {ConnectId}", _connectId);
            await CompleteWithError(VerificationFlowFailure.Generic("Verification flow not initialized"));
            return;
        }

        Result<string, VerificationFlowFailure> checkResult =
            await _persistor.Ask<Result<string, VerificationFlowFailure>>(
                new RequestResendOtpActorEvent(_verificationFlow.Value.UniqueIdentifier), TimeSpan.FromSeconds(15));
        if (checkResult.IsErr)
        {
            await CompleteWithError(checkResult.UnwrapErr());
            return;
        }

        string outcome = checkResult.Unwrap();
        switch (outcome)
        {
            case VerificationFlowMessageKeys.ResendAllowed:
                _timersStarted = false;
                CancelTimers();
                _writer?.TryComplete();
                _writer = actorEvent.ChannelWriter;
                await ContinueWithOtp();
                break;
            case VerificationFlowMessageKeys.VerificationFlowExpired:
                await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                    new VerificationCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value.UniqueIdentifier),
                        Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.SessionExpired,
                        Message = _localizationProvider.Localize(VerificationFlowMessageKeys.VerificationFlowExpired,
                            actorEvent.CultureName)
                    }));
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
                await CompleteWithError(VerificationFlowFailure.Generic($"Unknown outcome from RequestResendOtp: {outcome}"));
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
            Log.Warning("Timers not started: verification flow not available for ConnectId {ConnectId}", _connectId);
            return;
        }

        CancelOtpTimer();

        if (!_timersStarted)
        {
            StartSessionTimer();
        }

        StartOtpTimer();
        _timersStarted = true;
    }

    private void StartSessionTimer()
    {
        if (!_verificationFlow.HasValue)
            return;

        TimeSpan sessionDelay = _sessionDeadline - DateTime.UtcNow;
        if (sessionDelay > TimeSpan.Zero)
        {
            _sessionTimer = Context.System.Scheduler.ScheduleTellOnceCancelable(sessionDelay, Self,
                new VerificationFlowExpiredEvent(_cultureName), ActorRefs.NoSender);
            _sessionRemainingTime = sessionDelay;
        }
    }

    private void StartOtpTimer()
    {
        if (_activeOtp?.IsActive != true)
        {
            Log.Warning("OTP timer not started: OTP is not active. IsActive={IsActive} for ConnectId {ConnectId}",
                _activeOtp?.IsActive, _connectId);
            return;
        }

        _activeOtpRemainingSeconds = CalculateRemainingSeconds(_activeOtp.ExpiresAt);
        Log.Information("Starting OTP timer: {RemainingSeconds} seconds remaining for ConnectId {ConnectId}",
            _activeOtpRemainingSeconds, _connectId);

        if (_activeOtpRemainingSeconds > 0)
        {
            _otpTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(TimeSpan.Zero,
                TimeSpan.FromSeconds(1), Self, new VerificationCountdownUpdate(), ActorRefs.NoSender);

            PauseSessionTimer();
            Become(OtpActive);
            Log.Information("OTP timer started successfully for ConnectId {ConnectId}", _connectId);
        }
        else
        {
            Log.Warning("OTP timer not started: OTP already expired. ExpiresAt={ExpiresAt}, Now={Now} for ConnectId {ConnectId}",
                _activeOtp.ExpiresAt, DateTime.UtcNow, _connectId);
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
        if (_isCompleting || _cleanupCompleted || !_timersStarted)
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
                        SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value.UniqueIdentifier),
                        Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.Expired
                    }));
            }

            await ExpireCurrentOtp();
            Become(OtpExpiredWaitingForSession);
            return;
        }

        if (_verificationFlow.HasValue)
        {
            await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                new VerificationCountdownUpdate
                {
                    SecondsRemaining = _activeOtpRemainingSeconds,
                    SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value.UniqueIdentifier),
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
                    SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value.UniqueIdentifier),
                    Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.SessionExpired,
                    Message = _localizationProvider.Localize(VerificationFlowMessageKeys.VerificationFlowExpired,
                        actorEvent.CultureName)
                }));
        }

        _isCompleting = true;
        
        _cleanupFallbackTimer = Context.System.Scheduler.ScheduleTellOnceCancelable(
            TimeSpan.FromSeconds(10), Self, new FallbackCleanupEvent(), ActorRefs.NoSender);
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
        await TerminateActor(graceful: true, updateFlowToExpired: true);
    }

    private async Task HandleClientDisconnection(PrepareForTerminationMessage _)
    {
        _isCompleting = true;
        _writer = null;

        await TerminateActor(graceful: true);
    }

    private async Task<Result<Unit, VerificationFlowFailure>> PrepareAndSendOtp(string cultureName)
    {
        GetPhoneNumberActorEvent getPhoneNumberActorEvent = new(_phoneNumberIdentifier);

        Result<PhoneNumberQueryRecord, VerificationFlowFailure> phoneNumberQueryRecordResult =
            await _persistor.Ask<Result<PhoneNumberQueryRecord, VerificationFlowFailure>>(getPhoneNumberActorEvent);

        if (phoneNumberQueryRecordResult.IsErr)
            return Result<Unit, VerificationFlowFailure>.Err(phoneNumberQueryRecordResult.UnwrapErr());

        PhoneNumberQueryRecord phoneNumberQueryRecord = phoneNumberQueryRecordResult.Unwrap();

        if (!_verificationFlow.HasValue)
        {
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Verification flow not initialized"));
        }

        OneTimePassword otp = new();
        Result<(OtpQueryRecord Record, string PlainOtp), VerificationFlowFailure> generationResult =
            otp.Generate(phoneNumberQueryRecord, _verificationFlow.Value.UniqueIdentifier);
        if (generationResult.IsErr) return Result<Unit, VerificationFlowFailure>.Err(generationResult.UnwrapErr());

        (OtpQueryRecord otpRecord, string plainOtp) = generationResult.Unwrap();

        Result<CreateOtpResult, VerificationFlowFailure> createResult =
            await _persistor.Ask<Result<CreateOtpResult, VerificationFlowFailure>>(
                new CreateOtpActorEvent(otpRecord), TimeSpan.FromSeconds(20));

        if (createResult.IsErr) return Result<Unit, VerificationFlowFailure>.Err(createResult.UnwrapErr());

        _activeOtp = otp;
        _activeOtp.UniqueIdentifier = createResult.Unwrap().OtpUniqueId;

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

        const int maxSmsRetries = 3;
        int smsAttempt = 0;
        SmsDeliveryResult? smsResult = null;

        while (smsAttempt < maxSmsRetries)
        {
            smsAttempt++;
            smsResult = await _smsProvider.SendOtpAsync(phoneNumberQueryRecord.PhoneNumber, messageBuilder.ToString());

            if (smsResult.IsSuccess)
            {
                break;
            }

            Log.Warning(
                "SMS sending failed on attempt {Attempt}/{MaxAttempts} for ConnectId {ConnectId}, Status: {Status}, Error: {ErrorMessage}",
                smsAttempt, maxSmsRetries, _connectId, smsResult.Status, smsResult.ErrorMessage);

            if (smsAttempt >= maxSmsRetries) continue;
            int delayMs = (int)Math.Pow(2, smsAttempt - 1) * 1000;
            await Task.Delay(delayMs);
        }

        if (smsResult?.IsSuccess != true)
        {
            try
            {
                await UpdateOtpStatus(VerificationFlowStatus.Failed);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to expire OTP after SMS failure for ConnectId {ConnectId}", _connectId);
            }

            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.SmsSendFailed(
                    $"Failed to send SMS after {maxSmsRetries} attempts: {smsResult?.ErrorMessage}"));
        }

        return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
    }

    private async Task NotifyAlreadyVerified()
    {
        if (_verificationFlow.HasValue)
        {
            await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                new VerificationCountdownUpdate
                {
                    SecondsRemaining = 0,
                    SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value.UniqueIdentifier),
                    AlreadyVerified = true
                }));
        }

        await TerminateActor(graceful: false, publishCleanupEvent: false);
    }

    private async Task ExpireCurrentOtp()
    {
        if (_activeOtp != null)
        {
            await UpdateOtpStatus(VerificationFlowStatus.Expired);
            _activeOtp = null;
        }

        _otpTimer?.Cancel();
        ResumeSessionTimer();
    }

    private async Task UpdateOtpStatus(VerificationFlowStatus status)
    {
        if (_activeOtp != null)
            await _persistor.Ask<Result<Unit, VerificationFlowFailure>>(
                new UpdateOtpStatusActorEvent(_activeOtp.UniqueIdentifier, status), TimeSpan.FromSeconds(10));
    }

    private static uint CalculateRemainingSeconds(DateTime expiresAt)
    {
        return (uint)Math.Max(0, Math.Ceiling((expiresAt - DateTime.UtcNow).TotalSeconds));
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
        bool publishCleanupEvent = true)
    {
        if (_cleanupCompleted)
            return;

        _cleanupCompleted = true;

        CancelTimers();
        _sessionTimerPaused = false;

        if (updateFlowToExpired && _verificationFlow.HasValue)
        {
            await _persistor.Ask<Result<int, VerificationFlowFailure>>(
                new UpdateVerificationFlowStatusActorEvent(_verificationFlow.Value.UniqueIdentifier,
                    VerificationFlowStatus.Expired));
        }

        if (error is not null)
            _writer?.TryComplete(error);
        else
            _writer?.TryComplete();

        if (publishCleanupEvent)
        {
            Context.System.EventStream.Publish(new ProtocolCleanupRequiredEvent(_connectId));
        }

        if (graceful)
        {
            Context.Parent.Tell(new FlowCompletedGracefullyActorEvent(Self));
            Context.Unwatch(Self);
        }

        Context.Stop(Self);
    }

    private async Task CompleteWithError(VerificationFlowFailure failure)
    {
        await TerminateActor(graceful: false, error: failure.InnerException, publishCleanupEvent: false);
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

            _timersStarted = false;
            _sessionTimerPaused = false;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Error canceling timers for ConnectId {ConnectId}", _connectId);
        }
    }

    private void PauseSessionTimer()
    {
        if (_sessionTimer is { IsCancellationRequested: false })
        {
            _sessionRemainingTime = _sessionDeadline - DateTime.UtcNow;
            _sessionTimer.Cancel(false);
            _sessionTimerPaused = true;
        }
    }

    private void ResumeSessionTimer()
    {
        if (!_sessionTimerPaused || _isCompleting || !_verificationFlow.HasValue)
            return;

        TimeSpan remaining = _sessionDeadline - DateTime.UtcNow;
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
            using CancellationTokenSource timeoutCts = new(TimeSpan.FromSeconds(5));
            await writer.WriteAsync(update, timeoutCts.Token);
        }
        catch (InvalidOperationException)
        {
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Unexpected error writing to channel for ConnectId {ConnectId}", _connectId);
        }
    }


    protected override void PostStop()
    {
        try
        {
            CancelTimers();
            _writer?.TryComplete();
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Error during PostStop cleanup for ConnectId {ConnectId}", _connectId);
        }
        finally
        {
            base.PostStop();
        }
    }
}