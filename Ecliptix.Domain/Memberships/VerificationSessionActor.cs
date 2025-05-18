using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.Domain.Persistors;
using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Authentication;
using Microsoft.Extensions.Localization;

namespace Ecliptix.Domain.Memberships;

public record StartTimer;

public record StopTimer(uint ConnectId);

public record ResendOtpCommand(uint ConnectId);

public class VerificationSessionActor : ReceiveActor
{
    private readonly uint _connectId;
    private readonly Guid _phoneNumberIdentifier;
    private readonly Guid _appDeviceIdentifier;
    private readonly VerificationPurpose _purpose;
    private readonly ChannelWriter<VerificationCountdownUpdate> _writer;
    private readonly IActorRef _persistor;
    private readonly SNSProvider _snsProvider;
    private readonly IStringLocalizer _localizer;

    private Option<PhoneNumberQueryRecord> _phoneNumberQueryRecord = Option<PhoneNumberQueryRecord>.None;

    private Option<VerificationSessionQueryRecord> _verificationSessionQueryRecord =
        Option<VerificationSessionQueryRecord>.None;

    private ICancelable? _timerCancelable;
    private readonly TimeSpan _sessionTimeout = TimeSpan.FromMinutes(5);
    private DateTime _sessionExpiresAt;
    private const int MaxOtpAttempts = 5;
    private int _otpAttempts;
    private OneTimePassword? _activeOtp;
    private ulong _activeOtpRemainingSeconds;

    public VerificationSessionActor(
        uint connectId,
        Guid phoneNumberIdentifier,
        Guid appDeviceIdentifier,
        VerificationPurpose purpose,
        ChannelWriter<VerificationCountdownUpdate> writer,
        IActorRef persistor,
        SNSProvider snsProvider,
        IStringLocalizer localizer)
    {
        _connectId = connectId;
        _phoneNumberIdentifier = phoneNumberIdentifier;
        _appDeviceIdentifier = appDeviceIdentifier;
        _purpose = purpose;
        _writer = writer;
        _persistor = persistor;
        _snsProvider = snsProvider;
        _localizer = localizer;
        _sessionExpiresAt = DateTime.UtcNow + _sessionTimeout;

        Become(Initializing);
    }

    public static Props Build(
        uint connectId,
        Guid phoneNumberIdentifier,
        Guid appDeviceIdentifier,
        VerificationPurpose purpose,
        ChannelWriter<VerificationCountdownUpdate> writer,
        IActorRef persistor,
        SNSProvider snsProvider,
        IStringLocalizer localizer) =>
        Props.Create(() => new VerificationSessionActor(
            connectId, phoneNumberIdentifier, appDeviceIdentifier, purpose, writer,
            persistor, snsProvider, localizer));

    private void Initializing()
    {
        Receive<Result<Option<VerificationSessionQueryRecord>, ShieldFailure>>(HandleExistingSessionCheck);
        Receive<Result<PhoneNumberQueryRecord, ShieldFailure>>(HandlePhoneNumberQueryRecord);
        Receive<Status.Failure>(failure =>
        {
            _writer.TryComplete(failure.Cause);
            Context.Stop(Self);
        });

        _persistor.Ask<Result<PhoneNumberQueryRecord, ShieldFailure>>(
            new GetPhoneNumberActorCommand(_phoneNumberIdentifier)).PipeTo(Self);
    }

    private void HandlePhoneNumberQueryRecord(Result<PhoneNumberQueryRecord, ShieldFailure> result)
    {
        if (result.IsErr)
        {
            _writer.TryComplete(result.UnwrapErr().InnerException);
            Context.Stop(Self);
            return;
        }

        _phoneNumberQueryRecord = Option<PhoneNumberQueryRecord>.Some(result.Unwrap());
        _persistor.Ask<Result<Option<VerificationSessionQueryRecord>, ShieldFailure>>(
                new GetVerificationSessionCommand(_appDeviceIdentifier, _phoneNumberQueryRecord.Value!.UniqueIdentifier,
                    _purpose))
            .PipeTo(Self);
    }

    private void HandleExistingSessionCheck(Result<Option<VerificationSessionQueryRecord>, ShieldFailure> result)
    {
        if (result.IsErr)
        {
            _writer.TryComplete(result.UnwrapErr().InnerException);
            Context.Stop(Self);
            return;
        }

        Option<VerificationSessionQueryRecord> maybeSession = result.Unwrap();
        if (maybeSession.HasValue && maybeSession.Value!.ExpiresAt > DateTime.UtcNow)
        {
            _verificationSessionQueryRecord = maybeSession;
            _sessionExpiresAt = maybeSession.Value.ExpiresAt;
            PrepareOtpAndSendAsync().ContinueWith(t => new StartTimer()).PipeTo(Self);
            Become(Running);
        }
        else
        {
            //TODO:verification code
            Become(CreatingSession);
            _persistor.Ask<Result<Guid, ShieldFailure>>(
                    new CreateVerificationSessionRecordCommand(
                        _phoneNumberIdentifier, _appDeviceIdentifier, _purpose,
                        DateTime.UtcNow + _sessionTimeout, _connectId))
                .PipeTo(Self);
        }
    }

    private void CreatingSession()
    {
        Receive<Result<Guid, ShieldFailure>>(HandleSessionCreation);
    }

    private void HandleSessionCreation(Result<Guid, ShieldFailure> result)
    {
        if (result.IsErr)
        {
            _writer.TryComplete(result.UnwrapErr().InnerException);
            Context.Stop(Self);
            return;
        }

        _verificationSessionQueryRecord = Option<VerificationSessionQueryRecord>.Some(
            new VerificationSessionQueryRecord(
                result.Unwrap(), _phoneNumberIdentifier, _appDeviceIdentifier, _connectId)
            {
                ExpiresAt = _sessionExpiresAt,
                Purpose = _purpose
            });

        PrepareOtpAndSendAsync().ContinueWith(t => new StartTimer()).PipeTo(Self);
        Become(Running);
    }

    private void Running()
    {
        Receive<StartTimer>(_ => StartTimer());
        ReceiveAsync<VerificationCountdownUpdate>(HandleTimerTick);
        Receive<VerifyCodeActorCommand>(command =>
        {
            if (_verificationSessionQueryRecord.HasValue)
            {
                VerifyCodeWithSessionCommand sessionCommand = new(
                    _verificationSessionQueryRecord.Value!.UniqueIdentifier,
                    command.Code,
                    command.VerificationPurpose,
                    command.ConnectId
                );
                _persistor.Forward(sessionCommand);
            }
        });
        ReceiveAsync<ResendOtpCommand>(HandleResendOtp);
        Receive<StopTimer>(msg =>
        {
            if (msg.ConnectId == _connectId)
            {
                _timerCancelable?.Cancel();
                Context.Stop(Self);
            }
        });
    }

    private void StartTimer()
    {
        _timerCancelable?.Cancel();
        if (_activeOtp is not { IsActive: true })
        {
            return;
        }

        _activeOtpRemainingSeconds = CalculateRemainingSeconds(_activeOtp.ExpiresAt);
        if (_activeOtpRemainingSeconds <= 0)
        {
            _activeOtp.ConsumeOtp();
            _activeOtp = null;
            return;
        }

        _timerCancelable = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
            initialDelay: TimeSpan.Zero,
            interval: TimeSpan.FromSeconds(1),
            receiver: Self,
            message: new VerificationCountdownUpdate(),
            sender: ActorRefs.NoSender);
    }

    private async Task HandleTimerTick(VerificationCountdownUpdate _)
    {
        if (DateTime.UtcNow >= _sessionExpiresAt || _otpAttempts >= MaxOtpAttempts)
        {
            await TerminateSession(VerificationSessionStatus.Expired);
            return;
        }

        if (_activeOtp is not { IsActive: true })
        {
            if (_activeOtp != null)
            {
                _activeOtp.ConsumeOtp();
                await _persistor.Ask<Result<Unit, ShieldFailure>>(new UpdateVerificationSessionStatusActorCommand(
                    _verificationSessionQueryRecord.Value!.UniqueIdentifier, VerificationSessionStatus.Expired));
                _activeOtp = null;
            }

            _timerCancelable?.Cancel();
            return;
        }

        await _writer.WriteAsync(new VerificationCountdownUpdate
        {
            SecondsRemaining = _activeOtpRemainingSeconds,
            SessionIdentifier = Helpers.GuidToByteString(_verificationSessionQueryRecord.Value!.UniqueIdentifier)
        });

        if (_activeOtpRemainingSeconds == 0)
        {
            _activeOtp.ConsumeOtp();

            await _persistor.Ask<Result<Unit, ShieldFailure>>(
                new UpdateOtpStatusActorCommand(
                    _activeOtp.UniqueIdentifier, VerificationSessionStatus.Expired));

            _activeOtp = null;
            _timerCancelable?.Cancel();
            return;
        }

        _activeOtpRemainingSeconds--;
    }

    private async Task HandleResendOtp(ResendOtpCommand command)
    {
        if (command.ConnectId != _connectId)
        {
            return;
        }

        if (_otpAttempts >= MaxOtpAttempts)
        {
            await TerminateSession(VerificationSessionStatus.Postponed);
            return;
        }

        if (_activeOtp is { IsActive: true })
        {
            // Active OTP exists, ignore resend request
            return;
        }

        if (DateTime.UtcNow >= _sessionExpiresAt)
        {
            await TerminateSession(VerificationSessionStatus.Expired);
            return;
        }

        Result<OtpQueryRecord, ShieldFailure> result = await PrepareOtpAndSendAsync();
        if (result.IsOk)
        {
            Self.Tell(new StartTimer());
        }
        else
        {
            _writer.TryComplete(result.UnwrapErr().InnerException);
        }
    }

    private async Task<Result<OtpQueryRecord, ShieldFailure>> PrepareOtpAndSendAsync()
    {
        if (!_phoneNumberQueryRecord.HasValue)
        {
            return Result<OtpQueryRecord, ShieldFailure>.Err(ShieldFailure.Generic("Phone number not found"));
        }

        if (_otpAttempts >= MaxOtpAttempts)
        {
            await TerminateSession(VerificationSessionStatus.Postponed);
            return Result<OtpQueryRecord, ShieldFailure>.Err(ShieldFailure.Generic("Maximum OTP attempts reached"));
        }

        OneTimePassword oneTimePassword = new(_localizer);
        Result<OtpQueryRecord, ShieldFailure> sendResult = await oneTimePassword.SendAsync(
            _phoneNumberQueryRecord.Value!,
            async (phoneNumber, message) => await _snsProvider.SendSmsAsync(phoneNumber, message));

        if (sendResult.IsOk)
        {
            OtpQueryRecord originalRecord = sendResult.Unwrap();
            OtpQueryRecord otpRecord = new()
            {
                SessionIdentifier = _verificationSessionQueryRecord.Value!.UniqueIdentifier,
                PhoneNumberIdentifier = originalRecord.PhoneNumberIdentifier,
                OtpHash = originalRecord.OtpHash,
                OtpSalt = originalRecord.OtpSalt,
                ExpiresAt = originalRecord.ExpiresAt,
                Status = originalRecord.Status,
                IsActive = originalRecord.IsActive
            };
            _activeOtp = oneTimePassword;
            _otpAttempts++;

            Result<CreateOtpRecordResult, ShieldFailure> createOtpRecordResult =
                await _persistor.Ask<Result<CreateOtpRecordResult,ShieldFailure>>(new CreateOtpRecordActorCommand(otpRecord));
            
            _activeOtp.SetOtpQueryRecordIdentifier(createOtpRecordResult.Unwrap().OtpUniqueId);
        }

        return sendResult;
    }

    private async Task TerminateSession(VerificationSessionStatus status)
    {
        if (_verificationSessionQueryRecord.HasValue)
        {
            await _persistor.Ask<Result<Unit, ShieldFailure>>(new UpdateVerificationSessionStatusActorCommand(
                _verificationSessionQueryRecord.Value!.UniqueIdentifier, status));
        }

        _timerCancelable?.Cancel();
        _writer.TryComplete();
        Context.Stop(Self);
    }

    private static ulong CalculateRemainingSeconds(DateTime expiresAt)
    {
        TimeSpan remaining = expiresAt - DateTime.UtcNow;
        return (ulong)Math.Max(0, Math.Ceiling(remaining.TotalSeconds));
    }

    protected override void PostStop()
    {
        _timerCancelable?.Cancel();
        _writer.TryComplete();
    }
}