using System.Text;
using System.Threading.Channels;
using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow.PersistenceModels;
using Ecliptix.IdentityAccess.Domain.Memberships;
using Ecliptix.IdentityAccess.Domain.Actors.Membership;
using OtpVerificationPurpose = Ecliptix.IdentityAccess.Domain.Memberships.OtpVerificationPurpose;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Memberships.Otp;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryResults;
using Ecliptix.IdentityAccess.Domain.Providers.Twilio;
using Ecliptix.IdentityAccess.Domain.Services;
using Ecliptix.Protobuf.Membership;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Configuration;
using Google.Protobuf;
using Microsoft.Extensions.Options;

namespace Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow;

public sealed class VerificationFlowActor : ReceivePersistentActor, IWithStash
{
    private const int OtpCodeLength = 6;
    private readonly VerificationFlowTimeouts _timeouts;
    private readonly IOptionsMonitor<SecurityConfiguration> _securityConfig;

    private readonly uint _connectId;
    private readonly string _cultureName;
    private readonly ILocalizationService _localizationService;
    private readonly IActorRef _membershipActor;
    private readonly IActorRef _persistorActor;
    private readonly Guid _phoneNumberIdentifier;
    private readonly ISmsProvider _smsProvider;
    private OneTimePassword? _activeOtp;
    private uint _activeOtpRemainingSeconds;
    private CancellationToken _currentRequestCancellationToken;
    private bool _writerCompleted;
    private long _otpSendAttempts;

    private ICancelable? _otpTimer = Cancelable.CreateCanceled();
    private ICancelable? _sessionTimer = Cancelable.CreateCanceled();
    private Option<VerificationFlowQueryRecord> _verificationFlow = Option<VerificationFlowQueryRecord>.None;
    private DateTimeOffset _sessionDeadline;
    private bool _sessionTimerPaused;

    private ChannelWriter<Result<OtpCountdownUpdate, VerificationFlowFailure>>? _writer;
    private bool _isCompleting;
    private bool _timersStarted;
    private bool _cleanupCompleted;
    private CancellationTokenSource? _smsOperationCancellationTokenSource;
    private Option<OtpQueryRecord> _activeOtpRecord;
    private uint _lastPublishedRemainingSeconds;
    private bool _otpTimerStartLogged;
    private short _currentOtpAttemptCount;
    private int _timerExpiryHandling;

    private sealed record OtpExpiredNow;

#pragma warning disable CS0108
    public IStash Stash { get; set; } = null!;
#pragma warning restore CS0108

    public override string PersistenceId => $"verification-flow-{_connectId}";

    public VerificationFlowActor(
        uint connectId, Guid phoneNumberIdentifier, Guid appDeviceIdentifier, OtpVerificationPurpose purpose,
        ChannelWriter<Result<OtpCountdownUpdate, VerificationFlowFailure>> writer,
        IActorRef persistor, IActorRef membershipActor, ISmsProvider smsProvider,
        ILocalizationService localizationService, string cultureName,
        IOptionsMonitor<SecurityConfiguration> securityConfig,
        CancellationToken initialCancellationToken)
    {
        _connectId = connectId;
        _phoneNumberIdentifier = phoneNumberIdentifier;
        _writer = writer;
        _persistorActor = persistor;
        _membershipActor = membershipActor;
        _smsProvider = smsProvider;
        _localizationService = localizationService;
        _cultureName = cultureName;
        _securityConfig = securityConfig;
        _timeouts = securityConfig.CurrentValue.VerificationFlow;
        _currentRequestCancellationToken = initialCancellationToken;
        Serilog.Log.Information("[verification.flow.started] ConnectId {ConnectId} Purpose {Purpose}", _connectId,
            purpose);

        Recover<VerificationFlowActorSnapshot>(snapshot => ApplyPersistentState(snapshot.State));
        Recover<VerificationFlowStatePersistedEvent>(evt => ApplyPersistentState(evt.State));

        Become(WaitingForFlow);
        _persistorActor.Ask<Result<VerificationFlowQueryRecord, VerificationFlowFailure>>(
            new InitiateFlowCommand(appDeviceIdentifier, _phoneNumberIdentifier, purpose, _connectId,
                initialCancellationToken)
        ).PipeTo(Self);
    }

    public static Props Build(
        uint connectId, Guid phoneNumberIdentifier, Guid appDeviceIdentifier, OtpVerificationPurpose purpose,
        ChannelWriter<Result<OtpCountdownUpdate, VerificationFlowFailure>> writer,
        IActorRef persistor, IActorRef membershipActor, ISmsProvider smsProvider,
        ILocalizationService localizationService, string cultureName,
        IOptionsMonitor<SecurityConfiguration> securityConfig,
        CancellationToken initialCancellationToken)
    {
        return Props.Create(() => new VerificationFlowActor(connectId, phoneNumberIdentifier, appDeviceIdentifier,
            purpose, writer, persistor, membershipActor, smsProvider, localizationService, cultureName, securityConfig,
            initialCancellationToken));
    }

    private void WaitingForFlow()
    {
        Command<RecoveryCompleted>(_ => HandleRecoveryCompleted());
        Command<OtpExpiredNow>(_ => { });

        CommandAsync<Result<VerificationFlowQueryRecord, VerificationFlowFailure>>(async result =>
        {
            if (result.IsErr)
            {
                VerificationFlowFailure verificationFlowFailure = result.UnwrapErr();
                if (verificationFlowFailure is { IsUserFacing: true, IsSecurityRelated: true })
                {
                    string message = _localizationService.Localize(verificationFlowFailure.Message, _cultureName);

                    await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                        new OtpCountdownUpdate
                        {
                            SecondsRemaining = 0,
                            SessionId = ByteString.Empty,
                            Status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusFailed,
                            Message = message,
                            MessageKey = verificationFlowFailure.Message
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
                    CompleteWriter();
                    Become(OtpExpiredWaitingForSession);
                }

                return;
            }

            VerificationFlowQueryRecord currentFlow = result.Unwrap();
            _verificationFlow = Option<VerificationFlowQueryRecord>.Some(currentFlow);
            _activeOtpRecord = currentFlow.OtpActive;
            _currentOtpAttemptCount = currentFlow.OtpActive.IsSome
                ? currentFlow.OtpActive.Value!.AttemptCount
                : (short)0;
            _sessionDeadline = DateTimeOffset.UtcNow.Add(_timeouts.SessionTimeout);

            Serilog.Log.Debug("[verification.flow.state.loaded] ConnectId {ConnectId} FlowId {FlowId} Status {Status}",
                _connectId, currentFlow.UniqueIdentifier, currentFlow.Status);

            if (currentFlow.Status == VerificationFlowStatus.Verified)
            {
                await NotifyAlreadyVerified();
                return;
            }

            if (!currentFlow.OtpActive.IsSome)
            {
                await ContinueWithOtp(_currentRequestCancellationToken);
            }
            else
            {
                _activeOtp = OneTimePassword.FromExisting(currentFlow.OtpActive.Value!);
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
        _cleanupCompleted = false;
        _timersStarted = false;

        _smsOperationCancellationTokenSource?.Cancel();
        _smsOperationCancellationTokenSource?.Dispose();
        _smsOperationCancellationTokenSource = new CancellationTokenSource();

        CancellationToken effectiveCancellation =
            requestCancellationToken.CanBeCanceled ? requestCancellationToken : GetOperationCancellationToken();

        using CancellationTokenSource linkedCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(
            _smsOperationCancellationTokenSource.Token,
            effectiveCancellation);

        Result<Unit, VerificationFlowFailure> otpResult = await PrepareAndSendOtp(_cultureName, linkedCancellationTokenSource.Token);
        if (otpResult.IsErr)
        {
            VerificationFlowFailure failure = otpResult.UnwrapErr();

            if (failure.IsUserFacing)
            {
                string message;
                string messageKey = failure.Message;

                if (failure.FailureType == VerificationFlowFailureType.RateLimitExceeded
                    && uint.TryParse(failure.Message, out uint minutes))
                {
                    string messageTemplate = _localizationService.Localize(
                        VerificationFlowMessageKeys.MobileOtpLimitExhausted,
                        _cultureName);
                    message = string.Format(messageTemplate, minutes);
                    messageKey = VerificationFlowMessageKeys.MobileOtpLimitExhausted;
                }
                else
                {
                    message = _localizationService.Localize(failure.Message, _cultureName);
                }

                await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                    new OtpCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionId = _verificationFlow.IsSome
                            ? Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier)
                            : ByteString.Empty,
                        Status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusFailed,
                        Message = message,
                        MessageKey = messageKey
                    }));
            }

            if (failure.FailureType is VerificationFlowFailureType.NotFound or VerificationFlowFailureType.Generic)
            {
                await CompleteWithError(failure);
            }
            else
            {
                CancelOtpTimer();
                CompleteWriter();
                Become(OtpExpiredWaitingForSession);
                Stash.UnstashAll();
            }
        }
        else
        {
            _lastPublishedRemainingSeconds = 0;
            _otpTimerStartLogged = false;
            _currentOtpAttemptCount = 0;
            Become(Running);
            Stash.UnstashAll();
            Self.Tell(new StartOtpTimerEvent());
        }
    }

    private void Running()
    {
        Command<StartOtpTimerEvent>(_ => StartTimers());
        CommandAsync<OtpCountdownUpdate>(HandleTimerTick);
        CommandAsync<OtpExpiredNow>(HandleImmediateOtpExpiry);
        CommandAsync<VerificationFlowExpiredEvent>(HandleSessionExpired);
        CommandAsync<VerifyFlowCommand>(HandleVerifyOtp);
        CommandAsync<InitiateVerificationFlowCommand>(HandleOtpVerificationRequest);
        CommandAsync<PrepareForTerminationMessage>(HandleClientDisconnection);
        Command<IsFlowValidQuery>(HandleSessionValidityCheck);
        CommandAsync<ReplaceChannelWriterCommand>(HandleReplaceChannelWriter);
        Command<DeleteMessagesSuccess>(_ => HandleDeleteMessagesSuccess());
        Command<DeleteMessagesFailure>(HandleDeleteMessagesFailure);
        Command<DeleteSnapshotsSuccess>(_ => HandleDeleteSnapshotsSuccess());
        Command<DeleteSnapshotsFailure>(HandleDeleteSnapshotsFailure);
    }

    private void OtpActive()
    {
        Command<StartOtpTimerEvent>(_ => { });
        CommandAsync<OtpCountdownUpdate>(HandleTimerTick);
        CommandAsync<OtpExpiredNow>(HandleImmediateOtpExpiry);
        CommandAsync<VerificationFlowExpiredEvent>(HandleSessionExpired);
        CommandAsync<VerifyFlowCommand>(HandleVerifyOtp);
        CommandAsync<InitiateVerificationFlowCommand>(HandleOtpVerificationRequest);
        CommandAsync<PrepareForTerminationMessage>(HandleClientDisconnection);
        Command<IsFlowValidQuery>(HandleSessionValidityCheck);
        CommandAsync<ReplaceChannelWriterCommand>(HandleReplaceChannelWriter);
        Command<DeleteMessagesSuccess>(_ => HandleDeleteMessagesSuccess());
        Command<DeleteMessagesFailure>(HandleDeleteMessagesFailure);
        Command<DeleteSnapshotsSuccess>(_ => HandleDeleteSnapshotsSuccess());
        Command<DeleteSnapshotsFailure>(HandleDeleteSnapshotsFailure);
    }

    private void OtpExpiredWaitingForSession()
    {
        Command<StartOtpTimerEvent>(_ => { });
        CommandAsync<OtpCountdownUpdate>(_ => Task.CompletedTask);
        Command<OtpExpiredNow>(_ => { });
        CommandAsync<VerificationFlowExpiredEvent>(HandleSessionExpired);
        CommandAsync<VerifyFlowCommand>(actorEvent =>
        {
            string message =
                _localizationService.Localize(VerificationFlowMessageKeys.OtpExpired, actorEvent.CultureName);
            Sender.Tell(CreateVerifyResponse(OtpVerificationResult.Expired, message));
            return Task.CompletedTask;
        });
        CommandAsync<InitiateVerificationFlowCommand>(HandleOtpVerificationRequest);
        CommandAsync<PrepareForTerminationMessage>(HandleClientDisconnection);
        Command<DeleteMessagesSuccess>(_ => HandleDeleteMessagesSuccess());
        Command<DeleteMessagesFailure>(HandleDeleteMessagesFailure);
        Command<DeleteSnapshotsSuccess>(_ => HandleDeleteSnapshotsSuccess());
        Command<DeleteSnapshotsFailure>(HandleDeleteSnapshotsFailure);
    }

    private async Task HandleVerifyOtp(VerifyFlowCommand actorEvent)
    {
        try
        {
            if (_activeOtp?.IsActive != true)
            {
                string message =
                    _localizationService.Localize(VerificationFlowMessageKeys.OtpExpired, actorEvent.CultureName);
                Sender.Tell(CreateVerifyResponse(OtpVerificationResult.Expired, message));
                return;
            }

            DateTimeOffset utcNow = DateTimeOffset.UtcNow;
            if (_activeOtp.ExpiresAt <= utcNow)
            {
                string message =
                    _localizationService.Localize(VerificationFlowMessageKeys.OtpExpired, actorEvent.CultureName);
                await ExpireCurrentOtp();
                Become(OtpExpiredWaitingForSession);
                Sender.Tell(CreateVerifyResponse(OtpVerificationResult.Expired, message));
                return;
            }

            if (_currentOtpAttemptCount >= _timeouts.MaxOtpVerificationAttempts)
            {
                string message = _localizationService.Localize(VerificationFlowMessageKeys.OtpMaxAttemptsReached,
                    actorEvent.CultureName);

                await UpdateOtpStatus(OtpStatus.Invalid);

                await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                    new OtpCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionId = _verificationFlow.IsSome
                            ? Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier)
                            : ByteString.Empty,
                        Status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusMaxAttemptsReached,
                        Message = message,
                        MessageKey = VerificationFlowMessageKeys.OtpMaxAttemptsReached
                    }));

                Sender.Tell(CreateVerifyResponse(OtpVerificationResult.Expired, message));

                Serilog.Log.Warning(
                    "[verification.otp.max-attempts] ConnectId {ConnectId} FlowId {FlowId} Attempts {Attempts}",
                    _connectId,
                    _verificationFlow.IsSome ? _verificationFlow.Value!.UniqueIdentifier : Guid.Empty,
                    _currentOtpAttemptCount);

                CancelOtpTimer();
                CompleteWriter();
                Become(OtpExpiredWaitingForSession);
                ClearActiveOtpState();
                PersistState();

                return;
            }

            bool verificationSucceeded;
            try
            {
                string normalizedOtp = NormalizeOtpCode(actorEvent.OneTimePassword);
                if (normalizedOtp.Length != OtpCodeLength)
                {
                    await HandleFailedVerification(actorEvent.CultureName);
                    return;
                }

                verificationSucceeded = _activeOtp.Verify(normalizedOtp);
            }
            catch (Exception ex)
            {
                Serilog.Log.Error(ex, "[verification.otp.verify.failed] ConnectId {ConnectId}", _connectId);
                Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Generic(VerificationFlowMessageKeys.Generic)));
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
            Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Err(
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
            await UpdateOtpStatus(OtpStatus.Used);

            if (_verificationFlow.IsSome)
            {
                await _persistorActor.Ask<Result<Unit, VerificationFlowFailure>>(
                    new UpdateVerificationFlowStatusCommand(_verificationFlow.Value!.UniqueIdentifier,
                        VerificationFlowStatus.Verified, GetOperationCancellationToken()),
                    _timeouts.UpdateOtpStatusTimeout);
            }
        }
        catch
        {
            Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic(VerificationFlowMessageKeys.Generic)));
            return;
        }

        if (!_verificationFlow.IsSome || _activeOtp == null)
        {
            Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic(VerificationFlowMessageKeys.FlowNotFoundOrInvalid)));
            return;
        }

        if (_verificationFlow.Value!.Purpose == OtpVerificationPurpose.SecureKeyRecovery)
        {
            try
            {
                GetMembershipByVerificationFlowQuery getMembershipEvent = new(
                    _verificationFlow.Value!.UniqueIdentifier,
                    GetOperationCancellationToken());
                Result<MembershipQueryRecord, VerificationFlowFailure> result =
                    await _membershipActor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(
                        getMembershipEvent, _timeouts.MembershipCreationTimeout);

                result.Switch(
                    membership => { Sender.Tell(CreateSuccessResponse(membership)); },
                    failure => { Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Err(failure)); }
                );
            }
            catch (Exception ex)
            {
                bool isTimeout = ex is TimeoutException ||
                                 (ex is AggregateException aggEx &&
                                  aggEx.InnerExceptions.Any(e => e is TimeoutException));

                VerificationFlowFailure failure = isTimeout
                    ? VerificationFlowFailure.Generic(VerificationFlowMessageKeys.Generic)
                    : VerificationFlowFailure.Generic(VerificationFlowMessageKeys.MembershipNotFound);

                Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Err(failure));
            }

            ClearActiveOtpState();
            await TerminateActor(graceful: true, reason: "password_recovery_verified");
            return;
        }

        if (await HandleExistingMembershipAsync())
        {
            return;
        }

        CreateMembershipCommand createEvent = new(_connectId, _verificationFlow.Value!.UniqueIdentifier,
            _activeOtp.UniqueIdentifier, ProtoMembership.Types.CreationStatus.OtpVerified,
            GetOperationCancellationToken());

        try
        {
            Result<MembershipQueryRecord, VerificationFlowFailure> result =
                await _membershipActor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(
                    createEvent, _timeouts.MembershipCreationTimeout);

            result.Switch(
                membership => { Sender.Tell(CreateSuccessResponse(membership)); },
                failure => { Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Err(failure)); }
            );
        }
        catch (Exception ex)
        {
            bool isTimeout = ex is TimeoutException ||
                             (ex is AggregateException aggEx && aggEx.InnerExceptions.Any(e => e is TimeoutException));

            VerificationFlowFailure failure = isTimeout
                ? VerificationFlowFailure.Generic(VerificationFlowMessageKeys.Generic)
                : VerificationFlowFailure.FromMembership(MembershipFailure.CreationFailed(ex));

            Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Err(failure));
            ClearActiveOtpState();
            await TerminateActor(graceful: true, reason: "membership_creation_failed");
            return;
        }


        ClearActiveOtpState();
        await TerminateActor(graceful: true, reason: "otp_verified_new_membership");
    }

    private async Task HandleFailedVerification(string cultureName)
    {
        if (_activeOtp != null)
        {
            short updatedCount = (short)(_currentOtpAttemptCount + 1);
            try
            {
                Result<short, VerificationFlowFailure> incrementResult =
                    await _persistorActor.Ask<Result<short, VerificationFlowFailure>>(
                        new IncrementOtpAttemptCountCommand(
                            _activeOtp.UniqueIdentifier,
                            GetOperationCancellationToken()),
                        _timeouts.UpdateOtpStatusTimeout);

                if (incrementResult.IsOk)
                {
                    updatedCount = incrementResult.Unwrap();
                }
                else
                {
                    Serilog.Log.Warning(
                        "[verification.otp.attempt.increment.failed] ConnectId {ConnectId} OtpId {OtpId} Error {Error}",
                        _connectId,
                        _activeOtp.UniqueIdentifier,
                        incrementResult.UnwrapErr().Message);
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex,
                    "[verification.otp.attempt.increment.exception] ConnectId {ConnectId} OtpId {OtpId}",
                    _connectId,
                    _activeOtp.UniqueIdentifier);
            }

            _currentOtpAttemptCount = updatedCount;

            if (_activeOtpRecord.IsSome)
            {
                OtpQueryRecord record = _activeOtpRecord.Value!;
                _activeOtpRecord = Option<OtpQueryRecord>.Some(record with { AttemptCount = updatedCount });
            }

            PersistState();

            _persistorActor.Tell(new RecordFailedOtpAttemptCommand(
                _activeOtp.UniqueIdentifier,
                "invalid_code",
                GetOperationCancellationToken()));
        }
        else
        {
            _currentOtpAttemptCount++;
        }

        if (_currentOtpAttemptCount >= _timeouts.MaxOtpVerificationAttempts)
        {
            await UpdateOtpStatus(OtpStatus.Invalid);

            string maxAttemptsMessage =
                _localizationService.Localize(VerificationFlowMessageKeys.OtpMaxAttemptsReached, cultureName);


            if (_verificationFlow.IsSome)
            {
                await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                    new OtpCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionId = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                        Status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusMaxAttemptsReached,
                        Message = maxAttemptsMessage,
                        MessageKey = VerificationFlowMessageKeys.OtpMaxAttemptsReached
                    }));
            }

            CancelOtpTimer();
            CompleteWriter();
            Become(OtpExpiredWaitingForSession);
            ClearActiveOtpState();
            PersistState();

            Sender.Tell(CreateVerifyResponse(OtpVerificationResult.Expired, maxAttemptsMessage));
            return;
        }


        string message = _localizationService.Localize(VerificationFlowMessageKeys.InvalidOtp, cultureName);

        Sender.Tell(CreateVerifyResponse(OtpVerificationResult.InvalidOtp, message));
    }

    private async Task HandleOtpVerificationRequest(InitiateVerificationFlowCommand actorEvent)
    {
        if (actorEvent.ConnectId != _connectId)
        {
            return;
        }

        if (actorEvent.CancellationToken.CanBeCanceled)
        {
            _currentRequestCancellationToken = actorEvent.CancellationToken;
        }

        if (actorEvent.RequestType == OtpVerificationRequest.Types.Type.OtpRequestTypeSend)
        {
            if (_verificationFlow.IsSome && _verificationFlow.Value!.OtpCount > 0)
            {
                Result<(string Outcome, uint RemainingSeconds), VerificationFlowFailure> cooldownCheckResult =
                    await _persistorActor.Ask<Result<(string, uint), VerificationFlowFailure>>(
                        new RequestResendOtpCommand(_verificationFlow.Value!.UniqueIdentifier,
                            actorEvent.CancellationToken),
                        _timeouts.ResendOtpCheckTimeout);

                if (cooldownCheckResult.IsErr)
                {
                    Sender.Tell(Result<Unit, VerificationFlowFailure>.Err(cooldownCheckResult.UnwrapErr()));
                    return;
                }

                (string cooldownOutcome, uint cooldownRemainingSeconds) = cooldownCheckResult.Unwrap();
                if (cooldownOutcome != VerificationFlowMessageKeys.ResendAllowed)
                {
                    if (_writer != null && !_writerCompleted)
                    {
                        CompleteWriter();
                    }

                    _writer = actorEvent.ChannelWriter;
                    _writerCompleted = false;

                    OtpCountdownUpdate.Types.Status status;
                    string message;
                    string messageKey;
                    uint secondsRemaining = 0;

                    switch (cooldownOutcome)
                    {
                        case VerificationFlowMessageKeys.OtpMaxAttemptsReached:
                        {
                            status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusMaxAttemptsReached;
                            messageKey = VerificationFlowMessageKeys.OtpMaxAttemptsReached;
                            message = _localizationService.Localize(
                                VerificationFlowMessageKeys.OtpMaxAttemptsReached, actorEvent.CultureName);
                        }
                            break;
                        case VerificationFlowMessageKeys.ResendCooldown:
                        {
                            status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusResendCooldown;
                            messageKey = VerificationFlowMessageKeys.ResendCooldown;
                            message = _localizationService.Localize(
                                VerificationFlowMessageKeys.ResendCooldown, actorEvent.CultureName);
                            secondsRemaining = cooldownRemainingSeconds;
                        }
                            break;
                        default:
                            await CompleteWithError(
                                VerificationFlowFailure.Generic(
                                    $"Unknown outcome from RequestResendOtp: {cooldownOutcome}"));
                            return;
                    }

                    await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                        new OtpCountdownUpdate
                        {
                            SecondsRemaining = secondsRemaining,
                            SessionId = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                            Status = status,
                            Message = message,
                            MessageKey = messageKey
                        }));

                    Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
                    return;
                }

                if (_writer != null && !_writerCompleted)
                {
                    CompleteWriter();
                }
            }
            else if (_writer != null && !_writerCompleted)
            {
                Sender.Tell(Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Generic(
                        "A verification session is already in progress for this connection")));
                return;
            }

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

        if (actorEvent.RequestType != OtpVerificationRequest.Types.Type.OtpRequestTypeResend)
        {
            return;
        }

        if (!_verificationFlow.IsSome)
        {
            await CompleteWithError(VerificationFlowFailure.FlowNotFoundOrInvalid());
            return;
        }

        Result<(string Outcome, uint RemainingSeconds), VerificationFlowFailure> checkResult =
            await _persistorActor.Ask<Result<(string, uint), VerificationFlowFailure>>(
                new RequestResendOtpCommand(_verificationFlow.Value!.UniqueIdentifier, actorEvent.CancellationToken),
                _timeouts.ResendOtpCheckTimeout);
        if (checkResult.IsErr)
        {
            VerificationFlowFailure failure = checkResult.UnwrapErr();

            if (failure.IsUserFacing)
            {
                string message;
                string messageKey = failure.Message;

                if (failure.FailureType == VerificationFlowFailureType.RateLimitExceeded
                    && uint.TryParse(failure.Message, out uint minutes))
                {
                    string messageTemplate = _localizationService.Localize(
                        VerificationFlowMessageKeys.MobileOtpLimitExhausted,
                        _cultureName);
                    message = string.Format(messageTemplate, minutes);
                    messageKey = VerificationFlowMessageKeys.MobileOtpLimitExhausted;
                }
                else
                {
                    message = _localizationService.Localize(failure.Message, _cultureName);
                }

                if (_writer != null && !_writerCompleted)
                {
                    CompleteWriter();
                }

                _writer = actorEvent.ChannelWriter;
                _writerCompleted = false;

                await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                    new OtpCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionId = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                        Status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusFailed,
                        Message = message,
                        MessageKey = messageKey
                    }));

                Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
                return;
            }

            Sender.Tell(Result<Unit, VerificationFlowFailure>.Err(failure));
            return;
        }

        (string outcome, uint remainingSeconds) = checkResult.Unwrap();
        switch (outcome)
        {
            case VerificationFlowMessageKeys.ResendAllowed:
                _timersStarted = false;
                CancelTimers();

                if (_writer != null && !_writerCompleted)
                {
                    CompleteWriter();
                }

                _writer = actorEvent.ChannelWriter;
                _writerCompleted = false;
                _sessionDeadline = DateTimeOffset.UtcNow.Add(_timeouts.SessionTimeout);
                await ContinueWithOtp(actorEvent.CancellationToken);
                Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
                break;
            case VerificationFlowMessageKeys.OtpMaxAttemptsReached:
            {
                if (_writer != null && !_writerCompleted)
                {
                    CompleteWriter();
                }

                _writer = actorEvent.ChannelWriter;
                _writerCompleted = false;

                string message = _localizationService.Localize(
                    VerificationFlowMessageKeys.OtpMaxAttemptsReached, actorEvent.CultureName);
                await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                    new OtpCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionId = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                        Status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusMaxAttemptsReached,
                        Message = message,
                        MessageKey = VerificationFlowMessageKeys.OtpMaxAttemptsReached
                    }));
                Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
            }
                break;
            case VerificationFlowMessageKeys.ResendCooldown:
            {
                if (_writer != null && !_writerCompleted)
                {
                    CompleteWriter();
                }

                _writer = actorEvent.ChannelWriter;
                _writerCompleted = false;

                string message = _localizationService.Localize(
                    VerificationFlowMessageKeys.ResendCooldown, actorEvent.CultureName);
                await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                    new OtpCountdownUpdate
                    {
                        SecondsRemaining = remainingSeconds,
                        SessionId = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                        Status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusResendCooldown,
                        Message = message,
                        MessageKey = VerificationFlowMessageKeys.ResendCooldown
                    }));
                Sender.Tell(Result<Unit, VerificationFlowFailure>.Ok(Unit.Value));
            }
                break;
            default:
                await CompleteWithError(
                    VerificationFlowFailure.Generic($"Unknown outcome from RequestResendOtp: {outcome}"));
                break;
        }
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

        if (!_verificationFlow.IsSome)
        {
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
        if (!_verificationFlow.IsSome)
        {
            return;
        }

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
            return;
        }

        _activeOtpRemainingSeconds = CalculateRemainingSeconds(_activeOtp.ExpiresAt);

        if (_activeOtpRemainingSeconds > 0)
        {
            _timersStarted = true;
            _otpTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(TimeSpan.Zero,
                _timeouts.OtpUpdateInterval, Self, new OtpCountdownUpdate(), ActorRefs.NoSender);

            PauseSessionTimer();
            Become(OtpActive);

            if (!_otpTimerStartLogged)
            {
                Serilog.Log.Information(
                    "[verification.otp.timer-started] ConnectId {ConnectId} FlowId {FlowId} ExpiresAt {ExpiresAt}",
                    _connectId,
                    _verificationFlow.IsSome ? _verificationFlow.Value!.UniqueIdentifier : Guid.Empty,
                    _activeOtp.ExpiresAt);
                _otpTimerStartLogged = true;
            }

            Self.Tell(new OtpCountdownUpdate());
        }
        else
        {
            _timersStarted = false;
            Self.Tell(new OtpExpiredNow());
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

    private async Task HandleTimerTick(OtpCountdownUpdate _)
    {
        if (Interlocked.CompareExchange(ref _timerExpiryHandling, 1, 0) != 0)
        {
            return;
        }

        try
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
                if (_verificationFlow.IsSome)
                {
                    await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                        new OtpCountdownUpdate
                        {
                            SecondsRemaining = 0,
                            SessionId = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                            Status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusExpired
                        }));
                    Serilog.Log.Information(
                        "[verification.otp.countdown] ConnectId {ConnectId} FlowId {FlowId} Remaining {Remaining}",
                        _connectId, _verificationFlow.Value!.UniqueIdentifier, 0);
                    _lastPublishedRemainingSeconds = 0;
                }

                await ExpireCurrentOtp();
                Become(OtpExpiredWaitingForSession);
                return;
            }

            if (_verificationFlow.IsSome)
            {
                if (_lastPublishedRemainingSeconds != _activeOtpRemainingSeconds)
                {
                    Serilog.Log.Information(
                        "[verification.otp.countdown] ConnectId {ConnectId} FlowId {FlowId} Remaining {Remaining}",
                        _connectId, _verificationFlow.Value!.UniqueIdentifier, _activeOtpRemainingSeconds);
                    _lastPublishedRemainingSeconds = _activeOtpRemainingSeconds;
                }

                await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                    new OtpCountdownUpdate
                    {
                        SecondsRemaining = _activeOtpRemainingSeconds,
                        SessionId = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                        Status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusActive
                    }));
            }
        }
        finally
        {
            Interlocked.Exchange(ref _timerExpiryHandling, 0);
        }
    }

    private async Task HandleImmediateOtpExpiry(OtpExpiredNow _)
    {
        if (Interlocked.CompareExchange(ref _timerExpiryHandling, 1, 0) != 0)
        {
            return;
        }

        try
        {
            if (_isCompleting || _cleanupCompleted)
            {
                return;
            }

            if (_activeOtp?.IsActive != true)
            {
                return;
            }

            uint remainingSeconds = CalculateRemainingSeconds(_activeOtp.ExpiresAt);
            if (remainingSeconds > 0)
            {
                return;
            }

            _activeOtpRemainingSeconds = 0;
            _lastPublishedRemainingSeconds = 0;

            if (_verificationFlow.IsSome)
            {
                await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                    new OtpCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionId = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                        Status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusExpired
                    }));
                Serilog.Log.Information(
                    "[verification.otp.countdown] ConnectId {ConnectId} FlowId {FlowId} Remaining {Remaining}",
                    _connectId, _verificationFlow.Value!.UniqueIdentifier, 0);
            }

            await ExpireCurrentOtp();
            Become(OtpExpiredWaitingForSession);
        }
        finally
        {
            Interlocked.Exchange(ref _timerExpiryHandling, 0);
        }
    }

    private async Task HandleSessionExpired(VerificationFlowExpiredEvent actorEvent)
    {
        if (_sessionTimerPaused || _cleanupCompleted)
        {
            return;
        }

        CancelTimers();
        _sessionTimerPaused = false;

        if (_activeOtp != null)
        {
            await UpdateOtpStatus(OtpStatus.Expired);

            _activeOtp = null;
        }

        if (_verificationFlow.IsSome)
        {
            await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                new OtpCountdownUpdate
                {
                    SecondsRemaining = 0,
                    SessionId = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                    Status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusSessionExpired,
                    Message = _localizationService.Localize(VerificationFlowMessageKeys.VerificationFlowExpired,
                        actorEvent.CultureName),
                    MessageKey = VerificationFlowMessageKeys.VerificationFlowExpired
                }));

            CompleteWriter();
        }

        _isCompleting = true;

        await TerminateActor(graceful: true, updateFlowToExpired: true, reason: "session_expired");
    }

    private async Task HandleClientDisconnection(PrepareForTerminationMessage _)
    {
        _isCompleting = true;
        IActorRef replyTo = Sender;
        CompleteWriter();

        if (_activeOtp?.IsActive == true)
        {
            await UpdateOtpStatus(OtpStatus.Expired);
        }

        await TerminateActor(graceful: true, updateFlowToExpired: true, reason: "client_disconnect");

        if (!replyTo.IsNobody())
        {
            replyTo.Tell(FlowTerminationAcknowledged.Instance);
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> PrepareAndSendOtp(string cultureName,
        CancellationToken cancellationToken = default)
    {
        GetMobileNumberQuery getMobileNumberActorEvent = new(_phoneNumberIdentifier, cancellationToken);

        Result<MobileNumberQueryRecord, VerificationFlowFailure> phoneNumberQueryRecordResult =
            await _persistorActor.Ask<Result<MobileNumberQueryRecord, VerificationFlowFailure>>(getMobileNumberActorEvent);

        if (phoneNumberQueryRecordResult.IsErr)
        {
            return Result<Unit, VerificationFlowFailure>.Err(phoneNumberQueryRecordResult.UnwrapErr());
        }

        MobileNumberQueryRecord phoneNumberQueryRecord = phoneNumberQueryRecordResult.Unwrap();

        if (!_verificationFlow.IsSome)
        {
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.FlowNotFoundOrInvalid());
        }

        OneTimePassword otp = new(_timeouts.OtpExpiration) { UniqueIdentifier = Guid.NewGuid() };
        Result<(OtpQueryRecord Record, string PlainOtp), VerificationFlowFailure> generationResult =
            otp.Generate(phoneNumberQueryRecord, _verificationFlow.Value!.UniqueIdentifier);
        if (generationResult.IsErr)
        {
            return Result<Unit, VerificationFlowFailure>.Err(generationResult.UnwrapErr());
        }

        (OtpQueryRecord otpRecord, string plainOtp) = generationResult.Unwrap();
        otpRecord = otpRecord with { UniqueIdentifier = otp.UniqueIdentifier };

        Result<CreateOtpResult, VerificationFlowFailure> createResult =
            await _persistorActor.Ask<Result<CreateOtpResult, VerificationFlowFailure>>(
                new CreateOtpCommand(otpRecord, cancellationToken),
                _timeouts.CreateOtpTimeout);

        if (createResult.IsErr)
        {
            return Result<Unit, VerificationFlowFailure>.Err(createResult.UnwrapErr());
        }

        CreateOtpResult createOtp = createResult.Unwrap();

        _activeOtp = otp;
        _activeOtp.UniqueIdentifier = createOtp.OtpUniqueId;
        _activeOtpRecord = Option<OtpQueryRecord>.Some(otpRecord with
        {
            UniqueIdentifier = createOtp.OtpUniqueId, AttemptCount = 0
        });
        _currentOtpAttemptCount = 0;

        if (_verificationFlow.IsSome)
        {
            _verificationFlow = Option<VerificationFlowQueryRecord>.Some(_verificationFlow.Value with
            {
                OtpCount = _verificationFlow.Value.OtpCount + 1
            });
        }

        string localizedString =
            _localizationService.Localize(VerificationFlowMessageKeys.AuthenticationCodeIs, cultureName);
        StringBuilder messageBuilder = new(localizedString + ": " + plainOtp);

        int smsAttempt = 0;
        SmsDeliveryResult? smsResult = null;
        _otpSendAttempts++;

        try
        {
            while (smsAttempt < _timeouts.MaxSmsRetries)
            {
                smsAttempt++;
                smsResult = await _smsProvider.SendOtpAsync(phoneNumberQueryRecord.MobileNumber,
                    messageBuilder.ToString(), cancellationToken);

                if (smsResult.IsSuccess)
                {
                    break;
                }

                if (smsAttempt >= _timeouts.MaxSmsRetries)
                {
                    continue;
                }

                int delayMs = (int)Math.Pow(2, smsAttempt - 1) * 1000;
                await Task.Delay(delayMs, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            Log.Debug("SMS retry operation was cancelled for phone number ending in {PhoneNumberSuffix}",
                phoneNumberQueryRecord.MobileNumber.Length > 4
                    ? phoneNumberQueryRecord.MobileNumber[^4..]
                    : "****");

            try
            {
                if (_activeOtp?.IsActive == true)
                {
                    await UpdateOtpStatus(OtpStatus.Invalid);
                }
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "[verification.otp.cancelled.status-update-failed] ConnectId {ConnectId}", _connectId);
            }

            ClearActiveOtpState();

            PersistState();

            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic(VerificationFlowMessageKeys.Generic));
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning(ex, "[verification.otp.send.exception] ConnectId {ConnectId}", _connectId);

            try
            {
                if (_activeOtp?.IsActive == true)
                {
                    await UpdateOtpStatus(OtpStatus.Invalid);
                }
            }
            catch (Exception updateEx)
            {
                Log.Warning(updateEx, "[verification.otp.send.status-update-failed] ConnectId {ConnectId}", _connectId);
            }

            ClearActiveOtpState();
            PersistState();

            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.SmsSendFailed(innerException: ex));
        }

        if (smsResult?.IsSuccess != true)
        {
            try
            {
                await UpdateOtpStatus(OtpStatus.Invalid);
            }
            catch (Exception updateEx)
            {
                Log.Warning(updateEx,
                    "[verification.otp.sms-failed.status-update-failed] ConnectId {ConnectId} OtpId {OtpId}",
                    _connectId, _activeOtp?.UniqueIdentifier);
            }

            Serilog.Log.Warning(
                "[verification.otp.failed] ConnectId {ConnectId} FlowId {FlowId} Attempts {Attempts} Error {Error}",
                _connectId,
                _verificationFlow.Value?.UniqueIdentifier,
                smsAttempt,
                smsResult?.ErrorMessage.Match(err => err, () => "unknown") ?? "unknown");

            ClearActiveOtpState();
            PersistState();

            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.SmsSendFailed(
                    $"Failed to send SMS after {_timeouts.MaxSmsRetries} attempts: {smsResult?.ErrorMessage}"));
        }

        Serilog.Log.Information("[verification.otp.sent] ConnectId {ConnectId} FlowId {FlowId} Attempts {Attempts}",
            _connectId,
            _verificationFlow.Value?.UniqueIdentifier,
            smsAttempt);

        PersistState();

        return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
    }

    private async Task<bool> HandleExistingMembershipAsync()
    {
        try
        {
            Serilog.Log.Debug(
                "[verification.membership.check.start] ConnectId {ConnectId} FlowId {FlowId} PhoneId {PhoneId}",
                _connectId,
                _verificationFlow.IsSome ? _verificationFlow.Value!.UniqueIdentifier : Guid.Empty,
                _phoneNumberIdentifier);

            ExistsMembershipQuery checkMembershipEvent = new(
                _phoneNumberIdentifier, GetOperationCancellationToken());

            Result<ExistingMembershipResult, VerificationFlowFailure> membershipResult =
                await _persistorActor.Ask<Result<ExistingMembershipResult, VerificationFlowFailure>>(
                    checkMembershipEvent, _timeouts.CheckExistingMembershipTimeout);

            Serilog.Log.Information(
                "[verification.membership.check.completed] ConnectId {ConnectId}",
                _connectId);

            if (membershipResult.IsErr)
            {
                VerificationFlowFailure failure = membershipResult.UnwrapErr();
                Serilog.Log.Error(
                    "[verification.membership.check.failed] ConnectId {ConnectId} FlowId {FlowId} PhoneId {PhoneId} " +
                    "Error: {ErrorMessage} FailureType: {FailureType}",
                    _connectId,
                    _verificationFlow.IsSome ? _verificationFlow.Value!.UniqueIdentifier : Guid.Empty,
                    _phoneNumberIdentifier,
                    failure.Message,
                    failure.FailureType);

                Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Err(failure));
                ClearActiveOtpState();
                await TerminateActor(graceful: true, reason: "existing_membership_error");
                return true;
            }

            ExistingMembershipResult existingMembership = membershipResult.Unwrap();

            if (existingMembership is { MembershipExists: true, Membership: not null })
            {
                Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Ok(new OtpCodeVerifyResponse
                {
                    Result = OtpVerificationResult.Succeeded, Membership = existingMembership.Membership
                }));

                ClearActiveOtpState();
                await TerminateActor(graceful: true,
                    reason: "otp_verified_existing_membership");
                return true;
            }
        }
        catch (Exception ex)
        {
            bool isTimeout = ex is TimeoutException ||
                             (ex is AggregateException aggEx && aggEx.InnerExceptions.Any(e => e is TimeoutException));

            Serilog.Log.Error(ex,
                "[verification.membership.check.failed] ConnectId {ConnectId} FlowId {FlowId} " +
                "IsTimeout {IsTimeout} ExceptionType {ExceptionType}",
                _connectId,
                _verificationFlow.IsSome ? _verificationFlow.Value!.UniqueIdentifier : Guid.Empty,
                isTimeout,
                ex.GetType().Name);

            VerificationFlowFailure failure = isTimeout
                ? VerificationFlowFailure.Generic(VerificationFlowMessageKeys.Generic)
                : VerificationFlowFailure.FromMembership(MembershipFailure.QueryFailed(ex));

            Sender.Tell(Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Err(failure));
            ClearActiveOtpState();
            await TerminateActor(graceful: true, reason: "existing_membership_check_failed");
            return true;
        }

        return false;
    }

    private VerificationFlowPersistentState CapturePersistentState()
    {
        return new VerificationFlowPersistentState(
            _verificationFlow.Match<VerificationFlowQueryRecord?>(v => v, () => null),
            _activeOtpRecord.IsSome ? _activeOtpRecord.Value : null,
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

        _activeOtpRecord = state.ActiveOtp != null
            ? Option<OtpQueryRecord>.Some(state.ActiveOtp)
            : Option<OtpQueryRecord>.None;
        _activeOtp = state.ActiveOtp != null ? OneTimePassword.FromExisting(state.ActiveOtp) : null;
        _currentOtpAttemptCount = state.ActiveOtp?.AttemptCount ?? 0;
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
        PersistAsync(new VerificationFlowStatePersistedEvent(snapshot), _ =>
        {
            MaybeSaveSnapshot();
            afterApply?.Invoke();
        });
    }

    private void MaybeSaveSnapshot()
    {
        VerificationFlowActorSettings settings = _securityConfig.CurrentValue.VerificationFlowActor;
        if (LastSequenceNr == 0 || LastSequenceNr % settings.SnapshotInterval != 0)
        {
            return;
        }

        SaveSnapshot(new VerificationFlowActorSnapshot(CapturePersistentState()));
    }

    private async Task NotifyAlreadyVerified()
    {
        if (_verificationFlow.IsSome)
        {
            await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(
                new OtpCountdownUpdate
                {
                    SecondsRemaining = 0,
                    SessionId = Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier),
                    AlreadyVerified = true
                }));
        }

        await TerminateActor(graceful: false);
    }

    private void HandleRecoveryCompleted()
    {
        _cleanupCompleted = false;
        _isCompleting = false;

        if (_verificationFlow.IsSome && _sessionDeadline == default)
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
            await UpdateOtpStatus(OtpStatus.Expired);
            _activeOtp = null;
            _activeOtpRecord = Option<OtpQueryRecord>.None;
        }

        CancelOtpTimer();

        ResumeSessionTimer();
        PersistState();
    }

    private void ClearActiveOtpState()
    {
        _activeOtp = null;
        _activeOtpRecord = Option<OtpQueryRecord>.None;
        _otpTimerStartLogged = false;
        _lastPublishedRemainingSeconds = 0;
        _currentOtpAttemptCount = 0;
    }

    private CancellationToken GetOperationCancellationToken()
    {
        return _currentRequestCancellationToken.IsCancellationRequested
            ? CancellationToken.None
            : _currentRequestCancellationToken;
    }

    private async Task UpdateOtpStatus(OtpStatus status)
    {
        Result<Unit, VerificationFlowFailure> result =
            await _persistorActor.Ask<Result<Unit, VerificationFlowFailure>>(
                new UpdateOtpStatusCommand(_activeOtp!.UniqueIdentifier, status, GetOperationCancellationToken()),
                _timeouts.UpdateOtpStatusTimeout);

        if (result.IsErr)
        {
            VerificationFlowFailure failure = result.UnwrapErr();
            Serilog.Log.Warning(
                "[verification.otp.status-update-warning] ConnectId {ConnectId} Status {Status} Failure {Failure}",
                _connectId, status, failure.Message);
        }
    }

    private static uint CalculateRemainingSeconds(DateTimeOffset expiresAt)
    {
        return (uint)Math.Max(0, Math.Ceiling((expiresAt - DateTimeOffset.UtcNow).TotalSeconds));
    }

    private static string NormalizeOtpCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return string.Empty;
        }

        Span<char> buffer = code.Length <= 64 ? stackalloc char[code.Length] : new char[code.Length];
        int length = 0;
        foreach (char character in code)
        {
            if (char.IsDigit(character))
            {
                buffer[length++] = character;
            }
        }

        return length == 0 ? string.Empty : new string(buffer[..length]);
    }

    private static Result<OtpCodeVerifyResponse, VerificationFlowFailure> CreateVerifyResponse(
        OtpVerificationResult result,
        string message)
    {
        return Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Ok(new OtpCodeVerifyResponse
        {
            Result = result, Message = message
        });
    }

    private static Result<OtpCodeVerifyResponse, VerificationFlowFailure>
        CreateSuccessResponse(MembershipQueryRecord membership)
    {
        ProtoMembership membershipProto = new()
        {
            MembershipId = Helpers.GuidToByteString(membership.UniqueIdentifier),
            Status = membership.ActivityStatus,
            CreationStatus = membership.CreationStatus
        };

        if (membership.AvailableAccounts is { Count: > 0 })
        {
            foreach (AccountInfo account in membership.AvailableAccounts)
            {
                membershipProto.Accounts.Add(new Protobuf.Account.Account
                {
                    AccountId = Helpers.GuidToByteString(account.AccountId),
                    MembershipId = Helpers.GuidToByteString(account.MembershipId),
                    AccountType = account.Type,
                    Status = account.Status,
                    IsDefaultAccount = account.IsDefault
                });
            }
        }

        return Result<OtpCodeVerifyResponse, VerificationFlowFailure>.Ok(new OtpCodeVerifyResponse
        {
            Result = OtpVerificationResult.Succeeded,
            Membership = membershipProto
        });
    }

    private async Task TerminateActor(
        bool graceful = true,
        bool updateFlowToExpired = false,
        Exception? error = null,
        string reason = "unspecified")
    {
        if (_cleanupCompleted)
        {
            return;
        }

        _cleanupCompleted = true;

        CancelTimers();
        _sessionTimerPaused = false;

        if (updateFlowToExpired && _verificationFlow.IsSome)
        {
            try
            {
                Result<Unit, VerificationFlowFailure> result =
                    await _persistorActor.Ask<Result<Unit, VerificationFlowFailure>>(
                        new UpdateVerificationFlowStatusCommand(_verificationFlow.Value!.UniqueIdentifier,
                            VerificationFlowStatus.Expired, GetOperationCancellationToken()));

                if (result.IsErr)
                {
                    VerificationFlowFailure failure = result.UnwrapErr();
                    Serilog.Log.Warning(
                        "[verification.flow.expire-warning] ConnectId {ConnectId} FlowId {FlowId} Failure {Failure}",
                        _connectId, _verificationFlow.Value!.UniqueIdentifier, failure.Message);
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Error(ex, "[verification.flow.expire-failed] ConnectId {ConnectId} FlowId {FlowId}",
                    _connectId, _verificationFlow.Value!.UniqueIdentifier);
            }
        }

        if (!_writerCompleted)
        {
            CompleteWriter(error);
        }

        Serilog.Log.Information(
            "[verification.flow.terminated] ConnectId {ConnectId} FlowId {FlowId} Graceful {Graceful} Reason {Reason}",
            _connectId,
            _verificationFlow.IsSome ? _verificationFlow.Value!.UniqueIdentifier : Guid.Empty,
            graceful,
            reason);

        if (graceful)
        {
            Context.Parent.Tell(new FlowCompletedGracefullyEvent(Self));
        }


        if (LastSequenceNr > 0)
        {
            try
            {
                PersistState();

                DeleteMessages(LastSequenceNr);

                if (LastSequenceNr > 1)
                {
                    DeleteSnapshots(new SnapshotSelectionCriteria(LastSequenceNr - 1));
                }

                Serilog.Log.Debug(
                    "[verification.flow.journal-cleanup-requested] ConnectId {ConnectId} SequenceNr {SequenceNr}",
                    _connectId, LastSequenceNr);
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex,
                    "[verification.flow.journal-cleanup-error] ConnectId {ConnectId} - Non-critical, continuing termination",
                    _connectId);
            }
        }

        Self.Tell(PoisonPill.Instance);
    }

    private async Task CompleteWithError(VerificationFlowFailure failure)
    {
        bool isGraceful = failure.IsUserFacing;

        await TerminateActor(
            graceful: isGraceful,
            error: failure.InnerException,
            reason: $"failure_{failure.FailureType}");
    }

    private void HandleDeleteMessagesSuccess()
    {
        Serilog.Log.Information(
            "[verification.flow.journal-deleted] ConnectId {ConnectId} - Journal entries successfully deleted",
            _connectId);
    }

    private void HandleDeleteMessagesFailure(DeleteMessagesFailure failure)
    {
        Serilog.Log.Warning(
            "[verification.flow.journal-delete-failed] ConnectId {ConnectId} Error {Error} - Non-critical, journal will be cleaned by retention policy",
            _connectId, failure.Cause?.Message ?? "Unknown");
    }

    private void HandleDeleteSnapshotsSuccess()
    {
        Serilog.Log.Information(
            "[verification.flow.snapshots-deleted] ConnectId {ConnectId} - Old snapshots successfully deleted",
            _connectId);
    }

    private void HandleDeleteSnapshotsFailure(DeleteSnapshotsFailure failure)
    {
        Serilog.Log.Warning(
            "[verification.flow.snapshots-delete-failed] ConnectId {ConnectId} Error {Error} - Non-critical, snapshots will be cleaned by retention policy",
            _connectId, failure.Cause?.Message ?? "Unknown");
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

            if (_smsOperationCancellationTokenSource is { IsCancellationRequested: false })
            {
                _smsOperationCancellationTokenSource.Cancel();
            }

            _timersStarted = false;
            _sessionTimerPaused = false;
        }
        catch (Exception ex)
        {
            Serilog.Log.Debug(ex, "[verification.flow.cancel-timers-warning] ConnectId {ConnectId}", _connectId);
        }
    }

    private void CompleteWriter(Exception? error = null,
        [System.Runtime.CompilerServices.CallerMemberName]
        string callerMethod = "",
        [System.Runtime.CompilerServices.CallerLineNumber]
        int callerLine = 0)
    {
        if (_writerCompleted)
        {
            Serilog.Log.Debug("[verification.writer.already-completed] ConnectId {ConnectId} Caller {Caller}:{Line}",
                _connectId, callerMethod, callerLine);
            return;
        }

        ChannelWriter<Result<OtpCountdownUpdate, VerificationFlowFailure>>? writer =
            Interlocked.Exchange(ref _writer, null);

        _writerCompleted = true;

        if (writer == null)
        {
            Serilog.Log.Warning("[verification.writer.complete-null] ConnectId {ConnectId} Caller {Caller}:{Line}",
                _connectId, callerMethod, callerLine);
            return;
        }

        Serilog.Log.Information(
            "[verification.writer.completing] ConnectId {ConnectId} HasError {HasError} Caller {Caller}:{Line}",
            _connectId, error != null, callerMethod, callerLine);

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
        if (!_sessionTimerPaused || _isCompleting || !_verificationFlow.IsSome)
        {
            return;
        }

        TimeSpan remaining = _sessionDeadline - DateTimeOffset.UtcNow;
        if (remaining > TimeSpan.Zero)
        {
            _sessionTimer = Context.System.Scheduler.ScheduleTellOnceCancelable(remaining, Self,
                new VerificationFlowExpiredEvent(_cultureName), ActorRefs.NoSender);
        }

        _sessionTimerPaused = false;
    }

    private async Task SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure> update)
    {
        ChannelWriter<Result<OtpCountdownUpdate, VerificationFlowFailure>>? writer = _writer;
        if (writer == null)
        {
            return;
        }

        try
        {
            using CancellationTokenSource timeoutCancellationTokenSource =
                CancellationTokenSource.CreateLinkedTokenSource(_currentRequestCancellationToken);
            timeoutCancellationTokenSource.CancelAfter(_timeouts.ChannelWriteTimeout);
            await writer.WriteAsync(update, timeoutCancellationTokenSource.Token);
        }
        catch (InvalidOperationException)
        {
            Log.Warning(
                "[verification.channel.drop] Channel closed while writing update for ConnectId {ConnectId}",
                _connectId);
            CompleteWriter();
        }
        catch (OperationCanceledException)
        {
            Log.Warning("[verification.channel.drop] Write cancelled for ConnectId {ConnectId}", _connectId);
            if (!_currentRequestCancellationToken.IsCancellationRequested)
            {
                CompleteWriter();
            }
        }
        catch
        {
            CompleteWriter();
        }
    }

    private void HandleSessionValidityCheck(IsFlowValidQuery _)
    {
        TimeSpan remaining = _sessionDeadline - DateTimeOffset.UtcNow;
        bool otpActive = _activeOtp?.IsActive == true &&
                         CalculateRemainingSeconds(_activeOtp.ExpiresAt) > 0;
        bool isValid = remaining > TimeSpan.Zero && otpActive;

        Sender.Tell(new FlowValidityResponse(isValid));
    }

    private async Task HandleReplaceChannelWriter(ReplaceChannelWriterCommand command)
    {
        if (command.ConnectId != _connectId)
        {
            return;
        }

        Serilog.Log.Information(
            "[verification.flow.writer-replace] ConnectId {ConnectId} - Replacing channel writer for stream resume",
            _connectId);

        CompleteWriter();

        _writer = command.NewWriter;
        _writerCompleted = false;

        bool sessionExpired = _sessionDeadline != default && DateTimeOffset.UtcNow >= _sessionDeadline;
        uint remainingSeconds = _activeOtp?.IsActive == true
            ? CalculateRemainingSeconds(_activeOtp.ExpiresAt)
            : 0;
        _activeOtpRemainingSeconds = remainingSeconds;

        OtpCountdownUpdate.Types.Status status;
        string message = string.Empty;
        string? messageKey = null;
        if (sessionExpired)
        {
            status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusSessionExpired;
            message = _localizationService.Localize(VerificationFlowMessageKeys.VerificationFlowExpired, _cultureName);
            messageKey = VerificationFlowMessageKeys.VerificationFlowExpired;
        }
        else if (remainingSeconds > 0)
        {
            status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusActive;
        }
        else
        {
            status = OtpCountdownUpdate.Types.Status.OtpCountdownStatusExpired;
            message = _localizationService.Localize(VerificationFlowMessageKeys.OtpExpired, _cultureName);
            messageKey = VerificationFlowMessageKeys.OtpExpired;
        }

        OtpCountdownUpdate update = new()
        {
            SecondsRemaining = remainingSeconds,
            SessionId = _verificationFlow.IsSome
                ? Helpers.GuidToByteString(_verificationFlow.Value!.UniqueIdentifier)
                : ByteString.Empty,
            Status = status
        };

        if (!string.IsNullOrEmpty(message))
        {
            update.Message = message;
            update.MessageKey = messageKey ?? string.Empty;
        }

        await SafeWriteToChannelAsync(Result<OtpCountdownUpdate, VerificationFlowFailure>.Ok(update));

        Serilog.Log.Information(
            "[verification.flow.resumed] ConnectId {ConnectId} - Stream resumed at {RemainingSeconds}s",
            _connectId, remainingSeconds);
    }

    public override void AroundPostStop()
    {
        try
        {
            base.AroundPostStop();
        }
        catch (NullReferenceException)
        {
            try
            {
                PostStop();
            }
            catch (Exception postStopEx)
            {
                Log.Warning(postStopEx,
                    "[verification.flow.aroundpoststop.poststop-error] Error during PostStop after AroundPostStop exception. ConnectId: {ConnectId}",
                    _connectId);
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex,
                "[verification.flow.aroundpoststop.error] Unexpected error in AroundPostStop. ConnectId: {ConnectId}",
                _connectId);

            try
            {
                PostStop();
            }
            catch (Exception postStopEx)
            {
                Serilog.Log.Warning(postStopEx,
                    "[verification.flow.aroundpoststop.poststop-error] Error during PostStop after AroundPostStop exception. ConnectId: {ConnectId}",
                    _connectId);
            }
        }
    }

    protected override void PostStop()
    {
        try
        {
            CancelTimers();
            CompleteWriter();
            _smsOperationCancellationTokenSource?.Dispose();
            _smsOperationCancellationTokenSource = null;
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning(ex, "[verification.flow.poststop.cleanup] Error during cleanup. ConnectId: {ConnectId}",
                _connectId);
        }
        finally
        {
            try
            {
                base.PostStop();
            }
            catch (NullReferenceException ex)
            {
                Log.Debug(
                    "[verification.flow.poststop.suppress] Suppressed Akka.Persistence null reference during shutdown. ConnectId: {ConnectId}, Error: {Error}",
                    _connectId, ex.Message);
            }
            catch (Exception ex)
            {
                Log.Warning(ex,
                    "[verification.flow.poststop.error] Unexpected error in base.PostStop(). ConnectId: {ConnectId}",
                    _connectId);
            }
        }
    }
}
