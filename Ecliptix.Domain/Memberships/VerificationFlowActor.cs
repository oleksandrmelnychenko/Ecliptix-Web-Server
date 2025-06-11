using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.Domain.Memberships.Events;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.Utilities;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Extensions.Localization;
using Serilog;

namespace Ecliptix.Domain.Memberships;

public record StartOtpTimerEvent;
public record VerificationFlowExpiredEvent;
public record CreateMembershipActorEvent(
    uint ConnectId,
    Guid VerificationFlowIdentifier,
    Guid OtpIdentifier,
    Membership.Types.CreationStatus CreationStatus);
public record InitiateVerificationFlowActorEvent(
    uint ConnectId,
    Guid PhoneNumberIdentifier,
    Guid AppDeviceIdentifier,
    VerificationPurpose Purpose,
    InitiateVerificationRequest.Types.Type RequestType,
    ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> ChannelWriter);

public record VerifyFlowActorEvent(uint ConnectId, string OneTimePassword);

public class VerificationFlowActor : ReceiveActor
{
    private const int MaxOtpAttempts = 5;
    private static readonly TimeSpan SessionTimeout = TimeSpan.FromMinutes(5);

    private readonly uint _connectId;
    private readonly Guid _phoneNumberIdentifier;
    private readonly Guid _appDeviceIdentifier;
    private readonly VerificationPurpose _purpose;
    private readonly IActorRef _persistor;
    private readonly IActorRef _membershipActor;
    private readonly SNSProvider _snsProvider;
    private readonly IStringLocalizer _localizer;

    private ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> _writer;
    private Option<PhoneNumberQueryRecord> _phoneNumberRecord = Option<PhoneNumberQueryRecord>.None;
    private Option<VerificationFlowQueryRecord> _verificationFlowQueryRecord = Option<VerificationFlowQueryRecord>.None;

    private ICancelable? _otpTimer;
    private ICancelable? _sessionTimer;
    private OneTimePassword? _activeOtp;
    private int _otpAttempts;
    private ulong _activeOtpRemainingSeconds;
    private DateTime _sessionExpiresAt;

    public VerificationFlowActor(
        uint connectId,
        Guid phoneNumberIdentifier,
        Guid appDeviceIdentifier,
        VerificationPurpose purpose,
        ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> writer,
        IActorRef persistor,
        IActorRef membershipActor,
        SNSProvider snsProvider,
        IStringLocalizer localizer)
    {
        _connectId = connectId;
        _phoneNumberIdentifier = phoneNumberIdentifier;
        _appDeviceIdentifier = appDeviceIdentifier;
        _purpose = purpose;
        _writer = writer;
        _persistor = persistor;
        _membershipActor = membershipActor;
        _snsProvider = snsProvider;
        _localizer = localizer;
        _sessionExpiresAt = DateTime.UtcNow + SessionTimeout;

        Become(Initializing);
    }

    public static Props Build(
        uint connectId,
        Guid phoneNumberIdentifier,
        Guid appDeviceIdentifier,
        VerificationPurpose purpose,
        ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> writer,
        IActorRef persistor,
        IActorRef membershipActor,
        SNSProvider snsProvider,
        IStringLocalizer localizer) =>
        Props.Create(() => new VerificationFlowActor(
            connectId, phoneNumberIdentifier, appDeviceIdentifier, purpose, writer,
            persistor, membershipActor, snsProvider, localizer));

    private void Initializing()
    {
        Receive<Result<PhoneNumberQueryRecord, VerificationFlowFailure>>(HandlePhoneNumberResult);
        ReceiveAsync<Result<Option<VerificationFlowQueryRecord>, VerificationFlowFailure>>(
            ProcessExistingOrNewVerificationFlow);

        _persistor.Ask<Result<PhoneNumberQueryRecord, VerificationFlowFailure>>(
            new GetPhoneNumberActorEvent(_phoneNumberIdentifier)).PipeTo(Self);
    }

    private void HandlePhoneNumberResult(Result<PhoneNumberQueryRecord, VerificationFlowFailure> result)
    {
        if (result.IsErr)
        {
            CompleteWithError(result.UnwrapErr());
            return;
        }

        _phoneNumberRecord = Option<PhoneNumberQueryRecord>.Some(result.Unwrap());
        _persistor.Ask<Result<Option<VerificationFlowQueryRecord>, VerificationFlowFailure>>(
                new GetVerificationFlowActorEvent(_appDeviceIdentifier, _phoneNumberRecord.Value!.UniqueId, _purpose))
            .PipeTo(Self);
    }

    private async Task ProcessExistingOrNewVerificationFlow(
        Result<Option<VerificationFlowQueryRecord>, VerificationFlowFailure> result)
    {
        if (result.IsErr)
        {
            CompleteWithError(result.UnwrapErr());
            return;
        }

        Option<VerificationFlowQueryRecord> maybeSession = result.Unwrap();
        if (maybeSession.HasValue && maybeSession.Value.ExpiresAt > DateTime.UtcNow)
        {
            await HandleExistingVerificationFlow(maybeSession.Value);
        }
        else
        {
            CreateNewVerificationFlow();
        }
    }

    private async Task HandleExistingVerificationFlow(VerificationFlowQueryRecord session)
    {
        _verificationFlowQueryRecord = Option<VerificationFlowQueryRecord>.Some(session);
        _sessionExpiresAt = session.ExpiresAt;

        if (session.Status == VerificationFlowStatus.Verified)
        {
            await NotifyAlreadyVerified(session);
            return;
        }

        if (_otpAttempts >= MaxOtpAttempts)
        {
            await TerminateSession(VerificationFlowStatus.Postponed);
            return;
        }

        Result<OtpQueryRecord, VerificationFlowFailure> otpResult = await PrepareAndSendOtp();
        if (otpResult.IsOk)
        {
            Self.Tell(new StartOtpTimerEvent());
            Become(Running);
        }
        else
        {
            CompleteWithError(otpResult.UnwrapErr());
        }
    }

    private void CreateNewVerificationFlow()
    {
        Become(CreatingSession);
        _persistor.Ask<Result<Guid, VerificationFlowFailure>>(
                new CreateVerificationFlowActorEvent(
                    _phoneNumberIdentifier, _appDeviceIdentifier, _purpose,
                    _sessionExpiresAt, _connectId))
            .PipeTo(Self);
    }

    private void CreatingSession()
    {
        ReceiveAsync<Result<Guid, VerificationFlowFailure>>(HandleNewVerificationFlowCreation);
    }

    private async Task HandleNewVerificationFlowCreation(Result<Guid, VerificationFlowFailure> result)
    {
        if (result.IsErr)
        {
            CompleteWithError(result.UnwrapErr());
            return;
        }

        Guid flowUniqueId = result.Unwrap();
        VerificationFlowQueryRecord newFlowRecord = new()
        {
            UniqueIdentifier = flowUniqueId,
            PhoneNumberIdentifier = _phoneNumberIdentifier,
            AppDeviceIdentifier = _appDeviceIdentifier,
            ExpiresAt = _sessionExpiresAt,
            Purpose = _purpose,
            Status = VerificationFlowStatus.Pending,
            OtpCount = 0,
            ConnectId = _connectId
        };

        _verificationFlowQueryRecord = Option<VerificationFlowQueryRecord>.Some(newFlowRecord);

        Result<OtpQueryRecord, VerificationFlowFailure> otpResult = await PrepareAndSendOtp();
        if (otpResult.IsOk)
        {
            Self.Tell(new StartOtpTimerEvent());
            Become(Running);
        }
        else
        {
            CompleteWithError(otpResult.UnwrapErr());
        }
    }

    private void Running()
    {
        Receive<StartOtpTimerEvent>(_ => StartTimers());
        ReceiveAsync<VerificationCountdownUpdate>(HandleTimerTick);
        ReceiveAsync<VerificationFlowExpiredEvent>(HandleSessionExpired);
        ReceiveAsync<VerifyFlowActorEvent>(HandleVerifyOtp);
        ReceiveAsync<InitiateVerificationFlowActorEvent>(HandleResendRequest);
    }

    private async Task HandleVerifyOtp(VerifyFlowActorEvent command)
    {
        if (!IsVerificationFlowActive())
        {
            Sender.Tell(CreateVerifyResponse(VerificationResult.Expired, VerificationFlowMessageKeys.InvalidOtp));
            return;
        }

        bool isVerified = _activeOtp!.VerifyAsync(command.OneTimePassword);
        if (isVerified)
        {
            await HandleSuccessfulVerification();
        }
        else
        {
            await HandleFailedVerification();
        }
    }

    private async Task HandleSuccessfulVerification()
    {
        CancelTimers();

        await UpdateOtpStatus(VerificationFlowStatus.Verified);

        var createEvent = new CreateMembershipActorEvent(
            _connectId, _verificationFlowQueryRecord.Value!.UniqueIdentifier, _activeOtp!.UniqueIdentifier,
            Membership.Types.CreationStatus.OtpVerified);

        var result = await _membershipActor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(createEvent);

        if (result.IsOk)
        {
            Sender.Tell(CreateSuccessResponse(result.Unwrap()));
            Context.Stop(Self);
        }
        else
        {
            CompleteWithError(result.UnwrapErr());
        }
    }

    private async Task HandleFailedVerification()
    {
        await UpdateOtpStatus(VerificationFlowStatus.Failed);
        Sender.Tell(CreateVerifyResponse(VerificationResult.InvalidOtp, VerificationFlowMessageKeys.InvalidOtp));
    }

    private async Task HandleResendRequest(InitiateVerificationFlowActorEvent command)
    {
        if (command.RequestType != InitiateVerificationRequest.Types.Type.ResendOtp || command.ConnectId != _connectId)
            return;

        if (DateTime.UtcNow >= _sessionExpiresAt)
        {
            await TerminateSession(VerificationFlowStatus.Expired);
            return;
        }

        if (_otpAttempts >= MaxOtpAttempts)
        {
            await TerminateSession(VerificationFlowStatus.Postponed);
            return;
        }

        _writer = command.ChannelWriter;
        Result<OtpQueryRecord, VerificationFlowFailure> result = await PrepareAndSendOtp();
        if (result.IsOk)
        {
            StartTimers();
        }
        else
        {
            CompleteWithError(result.UnwrapErr());
        }
    }

    private void StartTimers()
    {
        CancelTimers();
        if (_activeOtp?.IsActive != true) return;

        TimeSpan sessionDelay = _sessionExpiresAt - DateTime.UtcNow;
        if (sessionDelay > TimeSpan.Zero)
        {
            _sessionTimer = Context.System.Scheduler.ScheduleTellOnceCancelable(sessionDelay, Self,
                new VerificationFlowExpiredEvent(), ActorRefs.NoSender);
        }

        _activeOtpRemainingSeconds = CalculateRemainingSeconds(_activeOtp.ExpiresAt);
        if (_activeOtpRemainingSeconds > 0)
        {
            _otpTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(TimeSpan.Zero,
                TimeSpan.FromSeconds(1), Self, new VerificationCountdownUpdate(), ActorRefs.NoSender);
        }
    }

    private async Task HandleTimerTick(VerificationCountdownUpdate _)
    {
        if (_activeOtp?.IsActive != true || _activeOtpRemainingSeconds <= 0)
        {
            await ExpireCurrentOtp();
            return;
        }

        --_activeOtpRemainingSeconds;
        await _writer.WriteAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
            new VerificationCountdownUpdate
            {
                SecondsRemaining = _activeOtpRemainingSeconds,
                SessionIdentifier = Helpers.GuidToByteString(_verificationFlowQueryRecord.Value!.UniqueIdentifier)
            }));
    }

    private async Task HandleSessionExpired(VerificationFlowExpiredEvent _)
    {
        await TerminateSession(VerificationFlowStatus.Expired);
    }

    private async Task<Result<OtpQueryRecord, VerificationFlowFailure>> PrepareAndSendOtp()
    {
        var otp = new OneTimePassword();
        var generationResult =
            otp.Generate(_phoneNumberRecord.Value!, _verificationFlowQueryRecord.Value!.UniqueIdentifier);

        if (generationResult.IsErr)
            return Result<OtpQueryRecord, VerificationFlowFailure>.Err(generationResult.UnwrapErr());

        var (otpRecord, plainOtp) = generationResult.Unwrap();
        var message = _localizer["Auth code is: {0}", plainOtp];

        var smsResult = await _snsProvider.SendSmsAsync(_phoneNumberRecord.Value!.PhoneNumber, message);
        if (smsResult.IsErr)
            return Result<OtpQueryRecord, VerificationFlowFailure>.Err(smsResult.UnwrapErr());

        var finalOtpRecord = CreateOtpRecord(otpRecord);
        _activeOtp = otp;

        var createResult =
            await _persistor.Ask<Result<CreateOtpRecordResult, VerificationFlowFailure>>(
                new CreateOtpActorEvent(finalOtpRecord));
        if (createResult.IsErr)
            return Result<OtpQueryRecord, VerificationFlowFailure>.Err(createResult.UnwrapErr());

        _otpAttempts++;
        _activeOtp.UniqueIdentifier = createResult.Unwrap().OtpUniqueId;
        return Result<OtpQueryRecord, VerificationFlowFailure>.Ok(finalOtpRecord);
    }

    private OtpQueryRecord CreateOtpRecord(OtpQueryRecord originalRecord) => new()
    {
        UniqueIdentifier = _verificationFlowQueryRecord.Value!.UniqueIdentifier,
        PhoneNumberIdentifier = originalRecord.PhoneNumberIdentifier,
        OtpHash = originalRecord.OtpHash,
        OtpSalt = originalRecord.OtpSalt,
        ExpiresAt = originalRecord.ExpiresAt,
        Status = originalRecord.Status,
        IsActive = originalRecord.IsActive,
        FlowUniqueId = originalRecord.FlowUniqueId
    };

    private async Task NotifyAlreadyVerified(VerificationFlowQueryRecord session)
    {
        await _writer.WriteAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
            new VerificationCountdownUpdate
            {
                SecondsRemaining = 0,
                SessionIdentifier = Helpers.GuidToByteString(session.UniqueIdentifier),
                AlreadyVerified = true
            }));
        Context.Stop(Self);
    }

    private async Task ExpireCurrentOtp()
    {
        if (_activeOtp != null)
        {
            _activeOtp.ConsumeOtp();
            await UpdateOtpStatus(VerificationFlowStatus.Expired);
            _activeOtp = null;
        }

        _otpTimer?.Cancel();
    }

    private async Task UpdateOtpStatus(VerificationFlowStatus status)
    {
        if (_activeOtp != null)
        {
            await _persistor.Ask<Result<Unit, VerificationFlowFailure>>(
                new UpdateOtpStatusActorEvent(_activeOtp.UniqueIdentifier, status));
        }
    }

    private async Task TerminateSession(VerificationFlowStatus status)
    {
        if (_verificationFlowQueryRecord.HasValue)
        {
            await _persistor.Ask<Result<Unit, VerificationFlowFailure>>(
                new UpdateVerificationFlowStatusActorEvent(_verificationFlowQueryRecord.Value!.UniqueIdentifier,
                    status));
        }

        Context.Stop(Self);
    }

    private bool IsVerificationFlowActive() => _verificationFlowQueryRecord.HasValue && _activeOtp?.IsActive == true;

    private static ulong CalculateRemainingSeconds(DateTime expiresAt)
    {
        var remaining = expiresAt - DateTime.UtcNow;
        return (ulong)Math.Max(0, Math.Ceiling(remaining.TotalSeconds));
    }

    private Result<VerifyCodeResponse, VerificationFlowFailure> CreateVerifyResponse(VerificationResult result,
        string messageKey) =>
        Result<VerifyCodeResponse, VerificationFlowFailure>.Ok(new VerifyCodeResponse
        {
            Result = result,
            Message = _localizer[messageKey]
        });

    private Result<VerifyCodeResponse, VerificationFlowFailure>
        CreateSuccessResponse(MembershipQueryRecord membership) =>
        Result<VerifyCodeResponse, VerificationFlowFailure>.Ok(new VerifyCodeResponse
        {
            Result = VerificationResult.Succeeded,
            Membership = new Membership
            {
                UniqueIdentifier = Helpers.GuidToByteString(membership.UniqueIdentifier),
                Status = membership.ActivityStatus
            }
        });

    private void CompleteWithError(VerificationFlowFailure failure)
    {
        _writer.TryComplete(failure.InnerException);
        Context.Stop(Self);
    }

    private void CancelTimers()
    {
        if (_otpTimer?.IsCancellationRequested == false) _otpTimer.Cancel();
        if (_sessionTimer?.IsCancellationRequested == false) _sessionTimer.Cancel();
    }

    protected override void PostStop()
    {
        CancelTimers();
        _writer.TryComplete();
        Log.Information("VerificationFlowActor for ConnectId {ConnectId} stopped.", _connectId);
        base.PostStop();
    }
}