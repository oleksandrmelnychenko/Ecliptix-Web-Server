using System.Text;
using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.Domain.Memberships.Events;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.Utilities;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Google.Protobuf;
using Microsoft.Extensions.Localization;
using Serilog;

namespace Ecliptix.Domain.Memberships;

public record InitiateVerificationFlowActorEvent(
    uint ConnectId,
    Guid PhoneNumberIdentifier,
    Guid AppDeviceIdentifier,
    VerificationPurpose Purpose,
    InitiateVerificationRequest.Types.Type RequestType,
    ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> ChannelWriter,
    string PeerCulture = "en-US"
);

public record VerifyFlowActorEvent(
    uint ConnectId,
    string OneTimePassword
);

public record CreateMembershipActorEvent(
    uint ConnectId,
    Guid VerificationFlowIdentifier,
    Guid OtpIdentifier,
    Membership.Types.CreationStatus CreationStatus
);

public record StartOtpTimerEvent;

public record VerificationFlowExpiredEvent;

public class VerificationFlowActor : ReceiveActor, IWithStash
{
    private readonly uint _connectId;
    private readonly Guid _phoneNumberIdentifier;
    private readonly IActorRef _persistor;
    private readonly IActorRef _membershipActor;
    private readonly SNSProvider _snsProvider;
    private readonly ILocalizationProvider _localizationProvider;

    private ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> _writer;
    private VerificationFlowQueryRecord _flow;
    private OneTimePassword? _activeOtp;

    private ICancelable? _otpTimer = Cancelable.CreateCanceled();
    private ICancelable? _sessionTimer = Cancelable.CreateCanceled();
    private ulong _activeOtpRemainingSeconds;

    public IStash Stash { get; set; } = null!;

    public VerificationFlowActor(
        uint connectId, Guid phoneNumberIdentifier, Guid appDeviceIdentifier, VerificationPurpose purpose,
        ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> writer,
        IActorRef persistor, IActorRef membershipActor, SNSProvider snsProvider,
        ILocalizationProvider localizationProvider)
    {
        _connectId = connectId;
        _phoneNumberIdentifier = phoneNumberIdentifier;
        _writer = writer;
        _persistor = persistor;
        _membershipActor = membershipActor;
        _snsProvider = snsProvider;
        _localizationProvider = localizationProvider;

        Become(WaitingForFlow);

        _persistor.Ask<Result<VerificationFlowQueryRecord, VerificationFlowFailure>>(
            new InitiateFlowAndReturnStateEvent(appDeviceIdentifier, _phoneNumberIdentifier, purpose, _connectId)
        ).PipeTo(Self);
    }

    public static Props Build(
        uint connectId, Guid phoneNumberIdentifier, Guid appDeviceIdentifier, VerificationPurpose purpose,
        ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> writer,
        IActorRef persistor, IActorRef membershipActor, SNSProvider snsProvider,
        ILocalizationProvider localizationProvider) =>
        Props.Create(() => new VerificationFlowActor(connectId, phoneNumberIdentifier, appDeviceIdentifier, purpose,
            writer, persistor, membershipActor, snsProvider, localizationProvider));

    private void WaitingForFlow()
    {
        ReceiveAsync<Result<VerificationFlowQueryRecord, VerificationFlowFailure>>(async result =>
        {
            if (result.IsErr)
            {
                VerificationFlowFailure verificationFlowFailure = result.UnwrapErr();
                if (verificationFlowFailure is { IsUserFacing: true, IsSecurityRelated: true })
                {
                    string localizedString = _localizationProvider.Localize(verificationFlowFailure.Message);

                    await _writer.WriteAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                        new VerificationCountdownUpdate
                        {
                            SecondsRemaining = 0,
                            SessionIdentifier = ByteString.Empty,
                            Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.Failed,
                            Message = localizedString
                        }));
                }
                else
                {
                    CompleteWithError(result.UnwrapErr());
                }

                return;
            }

            _flow = result.Unwrap();

            if (_flow.Status == VerificationFlowStatus.Verified)
            {
                await NotifyAlreadyVerified();
                return;
            }

            if (_flow.OtpActive is null)
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
        Result<Unit, VerificationFlowFailure> otpResult = await PrepareAndSendOtp();
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
    }

    private async Task HandleVerifyOtp(VerifyFlowActorEvent command)
    {
        if (_activeOtp?.IsActive != true)
        {
            Sender.Tell(CreateVerifyResponse(VerificationResult.Expired, VerificationFlowMessageKeys.InvalidOtp));
            return;
        }

        if (_activeOtp.Verify(command.OneTimePassword))
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
        _writer.Complete();

        CancelTimers();

        await UpdateOtpStatus(VerificationFlowStatus.Verified);

        CreateMembershipActorEvent createEvent = new(_connectId, _flow.UniqueIdentifier,
            _activeOtp!.UniqueIdentifier, Membership.Types.CreationStatus.OtpVerified);
        Result<MembershipQueryRecord, VerificationFlowFailure> result =
            await _membershipActor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(createEvent);

        result.Switch(
            membership => Sender.Tell(CreateSuccessResponse(membership)),
            failure => Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(failure))
        );

        Context.Stop(Self);
    }

    private async Task HandleFailedVerification()
    {
        await UpdateOtpStatus(VerificationFlowStatus.Failed);
        Sender.Tell(CreateVerifyResponse(VerificationResult.InvalidOtp, VerificationFlowMessageKeys.InvalidOtp));
    }

    private async Task HandleResendRequest(InitiateVerificationFlowActorEvent command)
    {
        if (command.RequestType != InitiateVerificationRequest.Types.Type.ResendOtp ||
            command.ConnectId != _connectId)
        {
            return;
        }

        Result<string, VerificationFlowFailure> checkResult =
            await _persistor.Ask<Result<string, VerificationFlowFailure>>(
                new RequestResendOtpActorEvent(_flow.UniqueIdentifier));
        if (checkResult.IsErr)
        {
            CompleteWithError(checkResult.UnwrapErr());
            return;
        }

        string outcome = checkResult.Unwrap();
        switch (outcome)
        {
            case VerificationFlowMessageKeys.ResendAllowed:
                _writer = command.ChannelWriter;
                await ContinueWithOtp();
                break;
            case VerificationFlowMessageKeys.VerificationFlowExpired:
                await TerminateVerificationFlow(VerificationFlowStatus.Expired,
                    VerificationFlowMessageKeys.VerificationFlowExpired);
                break;
            case VerificationFlowMessageKeys.OtpMaxAttemptsReached:
                await TerminateVerificationFlow(VerificationFlowStatus.MaxAttemptsReached,
                    VerificationFlowMessageKeys.OtpMaxAttemptsReached);
                break;
            case VerificationFlowMessageKeys.ResendCooldown:
                await _writer.WriteAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
                    new VerificationCountdownUpdate
                    {
                        SecondsRemaining = 0,
                        SessionIdentifier = Helpers.GuidToByteString(_flow.UniqueIdentifier),
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
        if (_activeOtp?.IsActive != true)
        {
            return;
        }

        TimeSpan sessionDelay = _flow.ExpiresAt - DateTime.UtcNow;
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
                SessionIdentifier = Helpers.GuidToByteString(_flow.UniqueIdentifier),
                Status = VerificationCountdownUpdate.Types.CountdownUpdateStatus.Active
            }));
    }

    private async Task HandleSessionExpired(VerificationFlowExpiredEvent _) =>
        await TerminateVerificationFlow(VerificationFlowStatus.Expired,
            VerificationFlowMessageKeys.VerificationFlowExpired);

    private async Task<Result<Unit, VerificationFlowFailure>> PrepareAndSendOtp()
    {
        GetPhoneNumberActorEvent getPhoneNumberActorEvent = new(_phoneNumberIdentifier);

        Result<PhoneNumberQueryRecord, VerificationFlowFailure> phoneNumberQueryRecordResult =
            await _persistor.Ask<Result<PhoneNumberQueryRecord, VerificationFlowFailure>>(getPhoneNumberActorEvent);

        if (phoneNumberQueryRecordResult.IsErr)
        {
            return Result<Unit, VerificationFlowFailure>.Err(phoneNumberQueryRecordResult.UnwrapErr());
        }

        PhoneNumberQueryRecord phoneNumberQueryRecord = phoneNumberQueryRecordResult.Unwrap();

        OneTimePassword otp = new();
        Result<(OtpQueryRecord Record, string PlainOtp), VerificationFlowFailure> generationResult =
            otp.Generate(phoneNumberQueryRecord, _flow.UniqueIdentifier);
        if (generationResult.IsErr)
        {
            return Result<Unit, VerificationFlowFailure>.Err(generationResult.UnwrapErr());
        }

        (OtpQueryRecord otpRecord, string plainOtp) = generationResult.Unwrap();

        string localizedString = _localizationProvider.Localize(VerificationFlowMessageKeys.AuthenticationCodeIs);
        StringBuilder messageBuilder = new(localizedString + ": " + plainOtp);

        Result<Unit, VerificationFlowFailure> smsResult =
            await _snsProvider.SendSmsAsync(phoneNumberQueryRecord.PhoneNumber, messageBuilder.ToString());

        if (smsResult.IsErr)
        {
            return Result<Unit, VerificationFlowFailure>.Err(smsResult.UnwrapErr());
        }

        _activeOtp = otp;

        Result<CreateOtpResult, VerificationFlowFailure> createResult =
            await _persistor.Ask<Result<CreateOtpResult, VerificationFlowFailure>>(
                new CreateOtpActorEvent(otpRecord));

        if (createResult.IsErr)
        {
            return Result<Unit, VerificationFlowFailure>.Err(createResult.UnwrapErr());
        }

        _flow = _flow with { OtpCount = _flow.OtpCount + 1 };

        _activeOtp.UniqueIdentifier = createResult.Unwrap().OtpUniqueId;

        return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
    }

    private async Task NotifyAlreadyVerified()
    {
        await _writer.WriteAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
            new VerificationCountdownUpdate
            {
                SecondsRemaining = 0,
                SessionIdentifier = Helpers.GuidToByteString(_flow.UniqueIdentifier),
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
        {
            await _persistor.Ask<Result<Unit, VerificationFlowFailure>>(
                new UpdateOtpStatusActorEvent(_activeOtp.UniqueIdentifier, status));
        }
    }

    private async Task TerminateVerificationFlow(VerificationFlowStatus status, string messageKey)
    {
        await _persistor.Ask<Result<int, VerificationFlowFailure>>(
            new UpdateVerificationFlowStatusActorEvent(_flow.UniqueIdentifier, status));

        await _writer.WriteAsync(Result<VerificationCountdownUpdate, VerificationFlowFailure>.Ok(
            new VerificationCountdownUpdate
            {
                SessionIdentifier = Helpers.GuidToByteString(_flow.UniqueIdentifier),
                Status = status == VerificationFlowStatus.Expired
                    ? VerificationCountdownUpdate.Types.CountdownUpdateStatus.Expired
                    : VerificationCountdownUpdate.Types.CountdownUpdateStatus.MaxAttemptsReached,
                Message = _localizationProvider.Localize(messageKey)
            }));

        Context.Stop(Self);
    }

    private static ulong CalculateRemainingSeconds(DateTime expiresAt) =>
        (ulong)Math.Max(0, Math.Ceiling((expiresAt - DateTime.UtcNow).TotalSeconds));

    private Result<VerifyCodeResponse, VerificationFlowFailure> CreateVerifyResponse(VerificationResult result,
        string messageKey) =>
        Result<VerifyCodeResponse, VerificationFlowFailure>.Ok(new VerifyCodeResponse
            { Result = result, Message = _localizationProvider.Localize(messageKey) });

    private Result<VerifyCodeResponse, VerificationFlowFailure>
        CreateSuccessResponse(MembershipQueryRecord membership) =>
        Result<VerifyCodeResponse, VerificationFlowFailure>.Ok(new VerifyCodeResponse
        {
            Result = VerificationResult.Succeeded,
            Membership = new Membership
            {
                UniqueIdentifier = Helpers.GuidToByteString(membership.UniqueIdentifier),
                Status = membership.ActivityStatus,
                CreationStatus = membership.CreationStatus
            }
        });

    //TODO: Test and make properly handle errors
    private void CompleteWithError(VerificationFlowFailure failure)
    {
        _writer.TryComplete(failure.InnerException);
        Context.Stop(Self);
    }

    private void CancelTimers()
    {
        if (_otpTimer?.IsCancellationRequested == false)
        {
            _otpTimer.Cancel();
        }

        if (_sessionTimer?.IsCancellationRequested == false)
        {
            _sessionTimer.Cancel();
        }
    }

    protected override void PostStop()
    {
        CancelTimers();
        _writer.Complete();
        Log.Information("VerificationFlowActor for ConnectId {ConnectId} stopped.", _connectId);
        base.PostStop();
    }
}