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
    private ulong _activeOtpRemainingSeconds;

    private ICancelable? _otpTimer = Cancelable.CreateCanceled();
    private ICancelable? _sessionTimer = Cancelable.CreateCanceled();
    private Option<VerificationFlowQueryRecord> _verificationFlow = Option<VerificationFlowQueryRecord>.None;

    private ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> _writer;

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

    public static Props Build(
        uint connectId, Guid phoneNumberIdentifier, Guid appDeviceIdentifier, VerificationPurpose purpose,
        ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> writer,
        IActorRef persistor, IActorRef membershipActor,  ISmsProvider smsProvider,
        ILocalizationProvider localizationProvider, string cultureName)
    {
        // AOT-compatible lambda - parameters captured but no closures
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

            _verificationFlow = Option<VerificationFlowQueryRecord>.Some(currentFlow);

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
        _writer.Complete();

        CancelTimers();

        await UpdateOtpStatus(VerificationFlowStatus.Verified);

        CreateMembershipActorEvent createEvent = new(_connectId, _verificationFlow.Value!.UniqueIdentifier,
            _activeOtp!.UniqueIdentifier, Membership.Types.CreationStatus.OtpVerified);
        Result<MembershipQueryRecord, VerificationFlowFailure> result =
            await _membershipActor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(createEvent, TimeSpan.FromSeconds(10));

        result.Switch(
            membership => Sender.Tell(CreateSuccessResponse(membership)),
            failure => Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(failure))
        );
        Context.Parent.Tell(new FlowCompletedGracefullyActorEvent(Self));
        Context.Unwatch(Self);
        Context.Stop(Self);
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
        CancelTimers();
        if (_activeOtp?.IsActive != true) return;

        TimeSpan sessionDelay = _verificationFlow.Value!.ExpiresAt - DateTime.UtcNow;
        if (sessionDelay > TimeSpan.Zero)
            _sessionTimer = Context.System.Scheduler.ScheduleTellOnceCancelable(sessionDelay, Self,
                new VerificationFlowExpiredEvent(string.Empty), ActorRefs.NoSender);

        _activeOtpRemainingSeconds = CalculateRemainingSeconds(_activeOtp.ExpiresAt);
        if (_activeOtpRemainingSeconds > 0)
            _otpTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(TimeSpan.Zero,
                TimeSpan.FromSeconds(1), Self, new VerificationCountdownUpdate(), ActorRefs.NoSender);
    }

    private async Task HandleTimerTick(VerificationCountdownUpdate _)
    {
        if (_activeOtp?.IsActive != true || _activeOtpRemainingSeconds <= 0)
        {
            await ExpireCurrentOtp();
            return;
        }

        --_activeOtpRemainingSeconds;
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

        string localizedString =
            _localizationProvider.Localize(VerificationFlowMessageKeys.AuthenticationCodeIs, cultureName);
        StringBuilder messageBuilder = new(localizedString + ": " + plainOtp);

        // Retry SMS sending with exponential backoff (max 3 attempts)
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
            
            Log.Warning("SMS sending failed on attempt {Attempt}/{MaxAttempts} for ConnectId {ConnectId}, Status: {Status}, Error: {ErrorMessage}",
                smsAttempt, maxSmsRetries, _connectId, smsResult.Status, smsResult.ErrorMessage);
            
            // Don't wait after the last attempt
            if (smsAttempt < maxSmsRetries)
            {
                int delayMs = (int)Math.Pow(2, smsAttempt - 1) * 1000; // 1s, 2s, 4s
                await Task.Delay(delayMs);
            }
        }

        if (smsResult?.IsSuccess != true)
        {
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.SmsSendFailed($"Failed to send SMS after {maxSmsRetries} attempts: {smsResult?.ErrorMessage}"));
        }

        _activeOtp = otp;

        Result<CreateOtpResult, VerificationFlowFailure> createResult =
            await _persistor.Ask<Result<CreateOtpResult, VerificationFlowFailure>>(
                new CreateOtpActorEvent(otpRecord), TimeSpan.FromSeconds(20));

        if (createResult.IsErr) return Result<Unit, VerificationFlowFailure>.Err(createResult.UnwrapErr());

        _verificationFlow = Option<VerificationFlowQueryRecord>.Some(_verificationFlow.Value with
        {
            OtpCount = _verificationFlow.Value!.OtpCount + 1
        });

        _activeOtp.UniqueIdentifier = createResult.Unwrap().OtpUniqueId;

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

    private static ulong CalculateRemainingSeconds(DateTime expiresAt)
    {
        return (ulong)Math.Max(0, Math.Ceiling((expiresAt - DateTime.UtcNow).TotalSeconds));
    }

    private static Result<VerifyCodeResponse, VerificationFlowFailure> CreateVerifyResponse(VerificationResult result,
        string message)
    {
        return Result<VerifyCodeResponse, VerificationFlowFailure>.Ok(new VerifyCodeResponse
            { Result = result, Message = message });
    }

    private Result<VerifyCodeResponse, VerificationFlowFailure>
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
        if (_otpTimer?.IsCancellationRequested == false) _otpTimer.Cancel();

        if (_sessionTimer?.IsCancellationRequested == false) _sessionTimer.Cancel();
    }
    
    private void ExpireAssociatedOtp()
    {
        _persistor.Tell(new ExpireAssociatedOtpActorEvent(_verificationFlow.Value!.UniqueIdentifier));
    }
    
    /// <summary>
    /// Safely writes to channel with timeout to prevent actor blocking
    /// </summary>
    private async Task<bool> SafeWriteToChannelAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure> update)
    {
        try
        {
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await _writer.WriteAsync(update, timeoutCts.Token);
            return true;
        }
        catch (InvalidOperationException)
        {
            // Channel is closed - this is expected during shutdown
            Log.Debug("Channel is closed for ConnectId {ConnectId}, cannot write update", _connectId);
            return false;
        }
        catch (OperationCanceledException)
        {
            // Timeout occurred - consumer is too slow
            Log.Warning("Channel write timeout for ConnectId {ConnectId}, consumer may be slow", _connectId);
            return false;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Unexpected error writing to channel for ConnectId {ConnectId}", _connectId);
            return false;
        }
    }
    private void PrepareForTermination()
    {
        CancelTimers();
        Log.Information("VerificationFlowActor for ConnectId {ConnectId} - timers clear", _connectId);
        ExpireAssociatedOtp();
        Log.Information("Expired associated OTP for FlowUniqueId {FlowUniqueId}", _verificationFlow.Value!.UniqueIdentifier);
        Log.Information("VerificationFlowActor for ConnectId {ConnectId} is preparing for termination", _connectId);
    }
    
    protected override void PostStop()
    {
        try
        {
            // Ensure cleanup happens even on unexpected termination
            PrepareForTermination();
            
            // Complete the channel writer to signal end of stream
            _writer?.TryComplete();
            
            Log.Information("VerificationFlowActor for ConnectId {ConnectId} stopped and resources cleaned up", _connectId);
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