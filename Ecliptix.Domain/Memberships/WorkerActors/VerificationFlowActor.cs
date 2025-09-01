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
    private Option<VerificationFlowQueryRecord> _verificationFlow = Option<VerificationFlowQueryRecord>.None;

    private ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> _writer;
    private volatile bool _isCompleting;
    private volatile bool _timersStarted;
    private readonly DateTime _actorCreatedAt = DateTime.UtcNow;
    private DateTime _timersStartedAt;
    private int _timerTickCount;

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

        Log.Information("VerificationFlowActor created for ConnectId {ConnectId}, Purpose: {Purpose}",
            _connectId, purpose);

        Become(WaitingForFlow);

        Log.Debug("Initiating verification flow for ConnectId {ConnectId}", _connectId);
        _persistor.Ask<Result<VerificationFlowQueryRecord, VerificationFlowFailure>>(
            new InitiateFlowAndReturnStateActorEvent(appDeviceIdentifier, _phoneNumberIdentifier, purpose, _connectId)
        ).PipeTo(Self);
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
                    CompleteWithError(result.UnwrapErr());
                }

                return;
            }

            VerificationFlowQueryRecord currentFlow = result.Unwrap();
            Log.Information("Verification flow initiated successfully for ConnectId {ConnectId}, Status: {Status}, " +
                            "OtpActive: {HasActiveOtp}, ExpiresAt: {ExpiresAt}",
                _connectId, currentFlow.Status, currentFlow.OtpActive != null, currentFlow.ExpiresAt);

            _verificationFlow = Option<VerificationFlowQueryRecord>.Some(currentFlow);

            if (currentFlow.Status == VerificationFlowStatus.Verified)
            {
                Log.Information("Flow already verified for ConnectId {ConnectId}", _connectId);
                await NotifyAlreadyVerified();
                return;
            }

            if (currentFlow.OtpActive is null)
            {
                Log.Debug("No active OTP found, generating new one for ConnectId {ConnectId}", _connectId);
                await ContinueWithOtp();
            }
            else
            {
                Log.Debug("Active OTP found, starting timer for ConnectId {ConnectId}", _connectId);
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
            CompleteWithError
        );
    }

    private void Running()
    {
        Receive<StartOtpTimerEvent>(_ => StartTimers());
        ReceiveAsync<VerificationCountdownUpdate>(HandleTimerTick);
        ReceiveAsync<VerificationFlowExpiredEvent>(HandleSessionExpired);
        ReceiveAsync<VerifyFlowActorEvent>(HandleVerifyOtp);
        ReceiveAsync<InitiateVerificationFlowActorEvent>(HandleResendRequest);
        Receive<PrepareForTerminationMessage>(_ => PrepareForTermination());
    }

    private async Task HandleVerifyOtp(VerifyFlowActorEvent actorEvent)
    {
        if (_activeOtp?.IsActive != true)
        {
            Sender.Tell(CreateVerifyResponse(VerificationResult.Expired, VerificationFlowMessageKeys.InvalidOtp));
            return;
        }

        if (_activeOtp.Verify(actorEvent.OneTimePassword))
            await HandleSuccessfulVerification();
        else
            await HandleFailedVerification(actorEvent.CultureName);
    }

    private async Task HandleSuccessfulVerification()
    {
        Log.Information("Handling successful verification for ConnectId {ConnectId}", _connectId);

        _isCompleting = true;

        CancelTimers();

        await Task.Delay(50);

        try
        {
            _writer.Complete();
            Log.Debug("Channel completed successfully for ConnectId {ConnectId}", _connectId);
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
                Log.Debug("OTP status updated successfully on attempt {Attempt} for ConnectId {ConnectId}",
                    attempt, _connectId);
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

        CreateMembershipActorEvent createEvent = new(_connectId, _verificationFlow.Value!.UniqueIdentifier,
            _activeOtp!.UniqueIdentifier, Membership.Types.CreationStatus.OtpVerified);

        try
        {
            Result<MembershipQueryRecord, VerificationFlowFailure> result =
                await _membershipActor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(
                    createEvent, TimeSpan.FromSeconds(10));

            result.Switch(
                membership =>
                {
                    Log.Information("Membership created successfully for ConnectId {ConnectId}", _connectId);
                    Sender.Tell(CreateSuccessResponse(membership));
                },
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

        Context.Parent.Tell(new FlowCompletedGracefullyActorEvent(Self));
        Context.Unwatch(Self);
        Context.Stop(Self);

        Log.Information("Verification flow completed successfully for ConnectId {ConnectId}", _connectId);
    }

    private async Task HandleFailedVerification(string cultureName)
    {
        await UpdateOtpStatus(VerificationFlowStatus.Failed);

        string message = _localizationProvider.Localize(VerificationFlowMessageKeys.InvalidOtp, cultureName);

        Sender.Tell(CreateVerifyResponse(VerificationResult.InvalidOtp, message));
    }

    private async Task HandleResendRequest(InitiateVerificationFlowActorEvent actorEvent)
    {
        if (actorEvent.RequestType != InitiateVerificationRequest.Types.Type.ResendOtp ||
            actorEvent.ConnectId != _connectId)
            return;

        Result<string, VerificationFlowFailure> checkResult =
            await _persistor.Ask<Result<string, VerificationFlowFailure>>(
                new RequestResendOtpActorEvent(_verificationFlow.Value!.UniqueIdentifier), TimeSpan.FromSeconds(15));
        if (checkResult.IsErr)
        {
            CompleteWithError(checkResult.UnwrapErr());
            return;
        }

        string outcome = checkResult.Unwrap();
        switch (outcome)
        {
            case VerificationFlowMessageKeys.ResendAllowed:
                _writer = actorEvent.ChannelWriter;
                await ContinueWithOtp();
                break;
            case VerificationFlowMessageKeys.VerificationFlowExpired:
                await TerminateVerificationFlow(VerificationFlowStatus.Expired,
                    VerificationFlowMessageKeys.VerificationFlowExpired, actorEvent.CultureName);
                break;
            case VerificationFlowMessageKeys.OtpMaxAttemptsReached:
                await TerminateVerificationFlow(VerificationFlowStatus.MaxAttemptsReached,
                    VerificationFlowMessageKeys.OtpMaxAttemptsReached, actorEvent.CultureName);
                break;
            case VerificationFlowMessageKeys.ResendCooldown:
                await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                    new VerificationCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                        Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.Failed,
                        Message = _localizationProvider.Localize(VerificationFlowMessageKeys.ResendCooldown)
                    }));
                break;
            default:
                CompleteWithError(VerificationFlowFailure.Generic($"Unknown outcome from RequestResendOtp: {outcome}"));
                break;
        }

        Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
    }

    private void StartTimers()
    {
        if (_isCompleting)
        {
            Log.Debug("Skipping timer start - actor is completing for ConnectId {ConnectId}", _connectId);
            return;
        }

        if (_timersStarted &&
            _otpTimer is { IsCancellationRequested: false } &&
            _sessionTimer is { IsCancellationRequested: false })
        {
            Log.Warning("Attempted to start timers that are already running for ConnectId {ConnectId}", _connectId);
            return;
        }

        if (_activeOtp?.IsActive != true)
        {
            Log.Debug("Cannot start timers - no active OTP for ConnectId {ConnectId}", _connectId);
            return;
        }

        if (!_verificationFlow.HasValue)
        {
            Log.Warning("Cannot start timers - no verification flow for ConnectId {ConnectId}", _connectId);
            return;
        }

        CancelTimers();
        Log.Debug("Starting timers for ConnectId {ConnectId}", _connectId);

        TimeSpan sessionDelay = TimeSpan.Zero;
        if (_verificationFlow.HasValue)
        {
#pragma warning disable CS8602 // Dereference of a possibly null reference
            sessionDelay = _verificationFlow.Value.ExpiresAt - DateTime.UtcNow;
#pragma warning restore CS8602 // Dereference of a possibly null reference
        }

        if (sessionDelay > TimeSpan.Zero)
        {
            _sessionTimer = Context.System.Scheduler.ScheduleTellOnceCancelable(sessionDelay, Self,
                new VerificationFlowExpiredEvent(string.Empty), ActorRefs.NoSender);
            Log.Debug("Session timer started with delay {Delay} for ConnectId {ConnectId}",
                sessionDelay, _connectId);
        }
        else
        {
            Log.Warning("Session already expired by {Overdue} for ConnectId {ConnectId}",
                sessionDelay.Duration(), _connectId);
        }

        _activeOtpRemainingSeconds = CalculateRemainingSeconds(_activeOtp.ExpiresAt);
        if (_activeOtpRemainingSeconds > 0)
        {
            _otpTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(TimeSpan.Zero,
                TimeSpan.FromSeconds(1), Self, new VerificationCountdownUpdate(), ActorRefs.NoSender);
            Log.Debug("OTP timer started with {Seconds} seconds remaining for ConnectId {ConnectId}",
                _activeOtpRemainingSeconds, _connectId);
        }
        else
        {
            Log.Debug("OTP already expired for ConnectId {ConnectId}", _connectId);
        }

        _timersStarted = true;
        _timersStartedAt = DateTime.UtcNow;
    }

    private async Task HandleTimerTick(VerificationCountdownUpdate _)
    {
        _timerTickCount++;

        if (_activeOtp?.IsActive != true)
        {
            Log.Debug("Timer tick #{TickCount} - OTP inactive, expiring for ConnectId {ConnectId}",
                _timerTickCount, _connectId);
            await ExpireCurrentOtp();
            return;
        }

        uint actualRemaining = CalculateRemainingSeconds(_activeOtp.ExpiresAt);

        _activeOtpRemainingSeconds = actualRemaining;

        if (_activeOtpRemainingSeconds <= 0)
        {
            Log.Debug("Timer tick #{TickCount} - OTP expired, remaining: {Remaining} for ConnectId {ConnectId}",
                _timerTickCount, _activeOtpRemainingSeconds, _connectId);

            await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                new VerificationCountdownUpdate
                {
                    SecondsRemaining = 0,
                    SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                    Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.Expired
                }));

            await ExpireCurrentOtp();
            return;
        }

        Log.Debug("Timer tick #{TickCount} - {Remaining}s remaining for ConnectId {ConnectId}",
            _timerTickCount, _activeOtpRemainingSeconds, _connectId);

        await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
            new VerificationCountdownUpdate
            {
                SecondsRemaining = _activeOtpRemainingSeconds,
                SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.Active
            }));
    }

    private async Task HandleSessionExpired(VerificationFlowExpiredEvent actorEvent)
    {
        await TerminateVerificationFlow(VerificationFlowStatus.Expired,
            VerificationFlowMessageKeys.VerificationFlowExpired, actorEvent.CultureName);
    }

    private async Task<Result<Unit, VerificationFlowFailure>> PrepareAndSendOtp(string cultureName)
    {
        GetPhoneNumberActorEvent getPhoneNumberActorEvent = new(_phoneNumberIdentifier);

        Result<PhoneNumberQueryRecord, VerificationFlowFailure> phoneNumberQueryRecordResult =
            await _persistor.Ask<Result<PhoneNumberQueryRecord, VerificationFlowFailure>>(getPhoneNumberActorEvent);

        if (phoneNumberQueryRecordResult.IsErr)
            return Result<Unit, VerificationFlowFailure>.Err(phoneNumberQueryRecordResult.UnwrapErr());

        PhoneNumberQueryRecord phoneNumberQueryRecord = phoneNumberQueryRecordResult.Unwrap();

        OneTimePassword otp = new();
        Result<(OtpQueryRecord Record, string PlainOtp), VerificationFlowFailure> generationResult =
            otp.Generate(phoneNumberQueryRecord, _verificationFlow.Value!.UniqueIdentifier);
        if (generationResult.IsErr) return Result<Unit, VerificationFlowFailure>.Err(generationResult.UnwrapErr());

        (OtpQueryRecord otpRecord, string plainOtp) = generationResult.Unwrap();

        Result<CreateOtpResult, VerificationFlowFailure> createResult =
            await _persistor.Ask<Result<CreateOtpResult, VerificationFlowFailure>>(
                new CreateOtpActorEvent(otpRecord), TimeSpan.FromSeconds(20));

        if (createResult.IsErr) return Result<Unit, VerificationFlowFailure>.Err(createResult.UnwrapErr());

        _activeOtp = otp;
        _activeOtp.UniqueIdentifier = createResult.Unwrap().OtpUniqueId;

        _verificationFlow = Option<VerificationFlowQueryRecord>.Some(_verificationFlow.Value with
        {
            OtpCount = _verificationFlow.Value!.OtpCount + 1
        });

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
                Log.Debug("SMS sent successfully on attempt {Attempt} for ConnectId {ConnectId}",
                    smsAttempt, _connectId);
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
            Log.Warning("SMS sending failed completely for ConnectId {ConnectId}, expiring created OTP", _connectId);
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
        await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
            new VerificationCountdownUpdate
            {
                SecondsRemaining = 0,
                SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                AlreadyVerified = true
            }));
        Context.Stop(Self);
    }

    private async Task ExpireCurrentOtp()
    {
        if (_activeOtp != null)
        {
            await UpdateOtpStatus(VerificationFlowStatus.Expired);
            _activeOtp = null;
        }

        _otpTimer?.Cancel();
    }

    private async Task UpdateOtpStatus(VerificationFlowStatus status)
    {
        if (_activeOtp != null)
            await _persistor.Ask<Result<Unit, VerificationFlowFailure>>(
                new UpdateOtpStatusActorEvent(_activeOtp.UniqueIdentifier, status));
    }

    private async Task TerminateVerificationFlow(VerificationFlowStatus status, string messageKey, string cultureName)
    {
        await _persistor.Ask<Result<int, VerificationFlowFailure>>(
            new UpdateVerificationFlowStatusActorEvent(_verificationFlow.Value!.UniqueIdentifier, status));

        await SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
            new VerificationCountdownUpdate
            {
                SessionIdentifier = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                Status = status == VerificationFlowStatus.Expired
                    ? VerificationCountdownUpdate.Types.CountdownUpdateStatus.Expired
                    : VerificationCountdownUpdate.Types.CountdownUpdateStatus.MaxAttemptsReached,
                Message = _localizationProvider.Localize(messageKey, cultureName)
            }));

        Context.Parent.Tell(new FlowCompletedGracefullyActorEvent(Self));
        Context.Unwatch(Self);
        Context.Stop(Self);
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

    private void CompleteWithError(VerificationFlowFailure failure)
    {
        if (failure.InnerException is not null)
            _writer.TryComplete(failure.InnerException);
        else
            _writer.TryComplete();

        Context.Stop(Self);
    }

    private void CancelTimers()
    {
        if (_otpTimer?.IsCancellationRequested == false)
        {
            _otpTimer.Cancel();
            Log.Debug("OTP timer cancelled for ConnectId {ConnectId}", _connectId);
        }

        if (_sessionTimer?.IsCancellationRequested == false)
        {
            _sessionTimer.Cancel();
            Log.Debug("Session timer cancelled for ConnectId {ConnectId}", _connectId);
        }

        _timersStarted = false;
    }

    private async Task<bool> ExpireAssociatedOtpAsync()
    {
        if (!_verificationFlow.HasValue)
        {
            Log.Debug("No verification flow to expire OTP for ConnectId {ConnectId}", _connectId);
            return true;
        }

        try
        {
#pragma warning disable CS8602 // Dereference of a possibly null reference
            Guid flowId = _verificationFlow.HasValue ? _verificationFlow.Value.UniqueIdentifier : Guid.Empty;
#pragma warning restore CS8602 // Dereference of a possibly null reference
            Result<Unit, VerificationFlowFailure> expireResult =
                await _persistor.Ask<Result<Unit, VerificationFlowFailure>>(
                    new ExpireAssociatedOtpActorEvent(flowId),
                    TimeSpan.FromSeconds(3));

            if (expireResult.IsOk)
            {
                Log.Debug("Successfully expired associated OTP for FlowUniqueId {FlowUniqueId}", flowId);
                return true;
            }

            Log.Warning("Failed to expire associated OTP: {Error}", expireResult.UnwrapErr().Message);
            return false;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error expiring associated OTP for ConnectId {ConnectId}", _connectId);
            return false;
        }
    }

    private async Task SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure> update)
    {
        if (_isCompleting)
        {
            Log.Debug("Skipping channel write - actor is completing for ConnectId {ConnectId}", _connectId);
            return;
        }

        try
        {
            using CancellationTokenSource timeoutCts = new(TimeSpan.FromSeconds(5));
            await _writer.WriteAsync(update, timeoutCts.Token);
        }
        catch (InvalidOperationException)
        {
            Log.Debug("Channel is closed for ConnectId {ConnectId}, cannot write update", _connectId);
        }
        catch (OperationCanceledException)
        {
            Log.Warning("Channel write timeout for ConnectId {ConnectId}, consumer may be slow", _connectId);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Unexpected error writing to channel for ConnectId {ConnectId}", _connectId);
        }
    }

    private async Task<bool> PrepareForTerminationAsync()
    {
        Log.Information("VerificationFlowActor for ConnectId {ConnectId} is preparing for termination", _connectId);

        _isCompleting = true;
        CancelTimers();
        Log.Information("VerificationFlowActor for ConnectId {ConnectId} - timers cancelled", _connectId);

        await Task.Delay(50);

        bool otpExpired = await ExpireAssociatedOtpAsync();
        if (!otpExpired)
        {
            Log.Warning("Failed to expire OTP during termination for ConnectId {ConnectId}", _connectId);
        }

        LogFinalMetrics();

        Log.Information("VerificationFlowActor for ConnectId {ConnectId} termination preparation complete", _connectId);
        return otpExpired;
    }

    private void LogFinalMetrics()
    {
        TimeSpan totalLifetime = DateTime.UtcNow - _actorCreatedAt;
        TimeSpan timerDuration = _timersStartedAt == default ? TimeSpan.Zero : DateTime.UtcNow - _timersStartedAt;

        Log.Information("VerificationFlowActor metrics for ConnectId {ConnectId}: " +
                        "TotalLifetime={Lifetime}ms, TimerDuration={TimerDuration}ms, " +
                        "TotalTicks={TickCount}, AvgTickInterval={AvgInterval}ms",
            _connectId,
            totalLifetime.TotalMilliseconds,
            timerDuration.TotalMilliseconds,
            _timerTickCount,
            _timerTickCount > 0 ? timerDuration.TotalMilliseconds / _timerTickCount : 0);
    }

    private void PrepareForTermination()
    {
        try
        {
            Task<bool> task = PrepareForTerminationAsync();
            task.Wait(TimeSpan.FromSeconds(5));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error in synchronous termination preparation for ConnectId {ConnectId}", _connectId);
        }
    }

    protected override void PostStop()
    {
        try
        {
            PrepareForTermination();

            _writer?.TryComplete();

            Log.Information("VerificationFlowActor for ConnectId {ConnectId} stopped and resources cleaned up",
                _connectId);
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