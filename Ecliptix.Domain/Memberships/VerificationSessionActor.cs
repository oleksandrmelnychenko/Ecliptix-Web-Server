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

public record SessionExpired;

public record InitiateResendVerificationRequestActorCommand(Guid SessionIdentifier, uint ConnectId);

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

    private ICancelable? _otpTimer;
    private ICancelable? _sessionTimer;

    private readonly TimeSpan _sessionTimeout = TimeSpan.FromMinutes(5);
    private DateTime _sessionExpiresAt;
    private const int MaxOtpAttempts = 5;
    private int _otpAttempts;
    private OneTimePassword? _activeOtp;
    private ulong _activeOtpRemainingSeconds;
    private DateTime _lastOtpSent = DateTime.MinValue;
    private static readonly TimeSpan MinResendInterval = TimeSpan.FromSeconds(30);

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
            Become(CreatingSession);
            _persistor.Ask<Result<Guid, ShieldFailure>>(
                    new CreateVerificationSessionCommand(
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
        ReceiveAsync<SessionExpired>(HandleSessionExpired);
        ReceiveAsync<VerifyCodeActorCommand>(async command =>
        {
            if (!_verificationSessionQueryRecord.HasValue || _activeOtp is null || !_activeOtp.IsActive)
            {
                Sender.Tell(new VerifyCodeResponse
                {
                    Result = VerificationResult.Expired,
                    Message = _localizer["No active session or OTP."]
                });
                return;
            }

            bool isVerified = await _activeOtp.VerifyAsync(command.Code);
            if (isVerified)
            {
                UpdateOtpStatusActorCommand sessionCommand = new(
                    _verificationSessionQueryRecord.Value!.UniqueIdentifier,
                    VerificationSessionStatus.Verified
                );
                
                _persistor.Forward(sessionCommand);
                
                Sender.Tell(new VerifyCodeResponse
                {
                    Result = VerificationResult.Succeeded,
                    Message = _localizer["Verification succeeded."]
                });
                
                PostStop();
                Context.Stop(Self);
            }
            else
            {
                UpdateOtpStatusActorCommand sessionCommand = new(
                    _verificationSessionQueryRecord.Value!.UniqueIdentifier,
                    VerificationSessionStatus.Failed
                );
                _persistor.Forward(sessionCommand);
                
                Sender.Tell(new VerifyCodeResponse
                {
                    Result = VerificationResult.InvalidCode,
                    Message = _localizer["Invalid code. Please try again."]
                });
            }
        });
        ReceiveAsync<InitiateResendVerificationRequestActorCommand>(
            HandleInitiateResendVerificationRequestActorCommand);
        ReceiveAsync<ResendOtpCommand>(HandleResendOtp);
        Receive<StopTimer>(msg =>
        {
            if (msg.ConnectId == _connectId)
            {
                _otpTimer?.Cancel();
                _sessionTimer?.Cancel();
                Context.Stop(Self);
            }
        });
    }

    private async Task HandleInitiateResendVerificationRequestActorCommand(
        InitiateResendVerificationRequestActorCommand command)
    {
        if (command.ConnectId != _connectId)
        {
            Sender.Tell(Result<ResendOtpResponse, ShieldFailure>.Err(
                ShieldFailure.Generic("Invalid connect ID")));
            return;
        }

        if (DateTime.UtcNow >= _sessionExpiresAt)
        {
            Sender.Tell(Result<ResendOtpResponse, ShieldFailure>.Err(
                ShieldFailure.Generic("Session has expired")));
            return;
        }

        if (_otpAttempts >= MaxOtpAttempts)
        {
            Sender.Tell(Result<ResendOtpResponse, ShieldFailure>.Err(
                ShieldFailure.Generic("Maximum OTP attempts reached")));
            return;
        }

        if (DateTime.UtcNow - _lastOtpSent < MinResendInterval)
        {
            Sender.Tell(Result<ResendOtpResponse, ShieldFailure>.Err(
                ShieldFailure.Generic("Too soon to resend OTP")));
            return;
        }

        if (_activeOtp is { IsActive: true })
        {
            Sender.Tell(Result<ResendOtpResponse, ShieldFailure>.Err(
                ShieldFailure.Generic("Active OTP already exists")));
            return;
        }

        Result<OtpQueryRecord, ShieldFailure> result = await PrepareOtpAndSendAsync();
        if (result.IsOk)
        {
            _lastOtpSent = DateTime.UtcNow;
            Self.Tell(new StartTimer());
            Sender.Tell(Result<ResendOtpResponse, ShieldFailure>.Ok(new ResendOtpResponse
            {
                Result = VerificationResult.Succeeded,
                SessionIdentifier = Helpers.GuidToByteString(_verificationSessionQueryRecord.Value!.UniqueIdentifier),
                Purpose = _purpose
            }));
        }
        else
        {
            Sender.Tell(Result<ResendOtpResponse, ShieldFailure>.Err(result.UnwrapErr()));
        }
    }

    private void StartTimer()
    {
        _otpTimer?.Cancel();
        _sessionTimer?.Cancel();

        if (_activeOtp is not { IsActive: true })
        {
            return;
        }

        TimeSpan sessionDelay = _sessionExpiresAt - DateTime.UtcNow;
        if (sessionDelay > TimeSpan.Zero)
        {
            _sessionTimer = Context.System.Scheduler.ScheduleTellOnceCancelable(
                sessionDelay,
                Self,
                new SessionExpired(),
                ActorRefs.NoSender);
        }

        _activeOtpRemainingSeconds = CalculateRemainingSeconds(_activeOtp.ExpiresAt);
        if (_activeOtpRemainingSeconds > 0)
        {
            _otpTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
                TimeSpan.Zero,
                TimeSpan.FromSeconds(1),
                Self,
                new VerificationCountdownUpdate(),
                ActorRefs.NoSender);
        }
    }

    private async Task HandleTimerTick(VerificationCountdownUpdate _)
    {
        if (_activeOtp is not { IsActive: true } || _activeOtpRemainingSeconds <= 0)
        {
            if (_activeOtp != null)
            {
                _activeOtp.ConsumeOtp();
                await _persistor.Ask<Result<Unit, ShieldFailure>>(
                    new UpdateOtpStatusActorCommand(_activeOtp.UniqueIdentifier, VerificationSessionStatus.Expired));
                _activeOtp = null;
            }

            _otpTimer?.Cancel();
            return;
        }

        await _writer.WriteAsync(new VerificationCountdownUpdate
        {
            SecondsRemaining = _activeOtpRemainingSeconds,
            SessionIdentifier = Helpers.GuidToByteString(_verificationSessionQueryRecord.Value!.UniqueIdentifier)
        });

        _activeOtpRemainingSeconds--;
    }

    private async Task HandleSessionExpired(SessionExpired _)
    {
        await TerminateSession(VerificationSessionStatus.Expired);
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
            return; // Active OTP exists, ignore resend request
        }

        if (DateTime.UtcNow >= _sessionExpiresAt)
        {
            await TerminateSession(VerificationSessionStatus.Expired);
            return;
        }

        if (DateTime.UtcNow - _lastOtpSent < MinResendInterval)
        {
            return; // Too soon to resend
        }

        Result<OtpQueryRecord, ShieldFailure> result = await PrepareOtpAndSendAsync();
        if (result.IsOk)
        {
            _lastOtpSent = DateTime.UtcNow;
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
                await _persistor.Ask<Result<CreateOtpRecordResult, ShieldFailure>>(
                    new CreateOtpActorCommand(otpRecord));

            if (createOtpRecordResult.IsOk)
            {
                _activeOtp.SetOtpQueryRecordIdentifier(createOtpRecordResult.Unwrap().OtpUniqueId);
            }
            else
            {
                return Result<OtpQueryRecord, ShieldFailure>.Err(createOtpRecordResult.UnwrapErr());
            }
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

        PostStop();
        
        Context.Stop(Self);
    }

    private static ulong CalculateRemainingSeconds(DateTime expiresAt)
    {
        TimeSpan remaining = expiresAt - DateTime.UtcNow;
        return (ulong)Math.Max(0, Math.Ceiling(remaining.TotalSeconds));
    }

    protected override void PostStop()
    {
        _otpTimer?.Cancel();
        _sessionTimer?.Cancel();
        _writer.TryComplete();
    }
}