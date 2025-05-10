using System.Threading.Channels;
using Akka.Actor;
using Akka.Event;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Persistors;
using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Verification;

public record StartTimer;

public record StopTimer(uint ConnectId);

public class MembershipVerificationSessionActor : ReceiveActor
{
    private readonly ChannelWriter<TimerTick> _writer;
    private readonly IActorRef _persistor;
    private readonly SNSProvider _snsProvider;
    private readonly VerificationSessionQueryRecord _verificationSessionQueryRecord;
    private ICancelable _timerCancelable;
    private readonly TimeSpan _sessionTimeout = TimeSpan.FromSeconds(60);
    private readonly TimeSpan _timerInterval = TimeSpan.FromSeconds(1);
    private readonly Guid _streamId = Guid.NewGuid();
    private readonly ILoggingAdapter _log = Context.GetLogger();

    public MembershipVerificationSessionActor(
        uint connectId,
        Guid streamId,
        string mobile,
        Guid uniqueRec,
        ChannelWriter<TimerTick> writer,
        IActorRef persistor,
        SNSProvider snsProvider)
    {
        _writer = writer;
        _persistor = persistor;
        _snsProvider = snsProvider;

        _verificationSessionQueryRecord = new VerificationSessionQueryRecord(
            connectId, streamId, mobile, uniqueRec, GenerateVerificationCode())
        {
            ExpiresAt = DateTime.UtcNow.Add(_sessionTimeout),
            Status = MembershipVerificationSessionStatus.Pending
        };

        Become(Initializing);
    }

    public static Props Build(
        uint connectId,
        Guid streamId,
        string mobile,
        Guid deviceId,
        ChannelWriter<TimerTick> writer,
        IActorRef persistor,
        SNSProvider snsProvider) =>
        Props.Create(() =>
            new MembershipVerificationSessionActor(connectId, streamId, mobile, deviceId, writer, persistor,
                snsProvider));

    private void Initializing()
    {
        Context.System.Log.Info("Entering Initializing state");

        Receive<Result<VerificationSessionQueryRecord, ShieldFailure>>(HandleExistingSessionCheck);
        Receive<Status.Failure>(failure =>
        {
            _log.Error(failure.Cause,
                "Failed to get existing verification session from persistor. Actor: {0}, ConnectId: {1}, DeviceId: {2}",
                Self.Path.Name,
                _verificationSessionQueryRecord.ConnectId,
                _verificationSessionQueryRecord.AppDeviceUniqueRec);
            _writer.TryComplete(failure.Cause);
            Context.Stop(Self);
        });
        ReceiveAny(msg => Context.System.Log.Warning($"Unexpected message: {msg.GetType()}"));

        Context.System.Log.Info("Requesting existing verification session");
        _persistor.Ask<Result<VerificationSessionQueryRecord, ShieldFailure>>(
                new GetVerificationSessionCommand(_verificationSessionQueryRecord.AppDeviceUniqueRec))
            .PipeTo(Self);
    }

    private void HandleExistingSessionCheck(Result<VerificationSessionQueryRecord, ShieldFailure> result)
    {
        if (result.IsErr)
        {
            _log.Error($"Failed to check for existing session: {result.UnwrapErr().Message}");
            Context.Stop(Self);
            return;
        }

        VerificationSessionQueryRecord existingSession = result.Unwrap();
        if (!existingSession.IsEmpty && existingSession.ExpiresAt > DateTime.UtcNow)
        {
            _log.Info("Existing session found, transitioning to Running state");
            SendVerificationSms(existingSession.Mobile, existingSession.Code, existingSession.ExpiresAt)
                .PipeTo(Self, success: () => new StartTimer());
            Become(Running);
        }
        else
        {
            _log.Info("No valid session found, transitioning to CreatingSession state");
            Become(CreatingSession);
            _persistor.Ask<Result<Unit, ShieldFailure>>(
                    new CreateMembershipVerificationSessionRecordCommand(_verificationSessionQueryRecord))
                .PipeTo(Self);
        }
    }

    private void CreatingSession()
    {
        Receive<Result<Unit, ShieldFailure>>(HandleSessionCreation);
        Receive<Status.Failure>(failure =>
        {
            _log.Error(failure.Cause, "Failed to create session.");
            Context.Stop(Self);
        });
    }

    private void HandleSessionCreation(Result<Unit, ShieldFailure> result)
    {
        if (result.IsErr)
        {
            Context.System.Log.Error($"Failed to create verification session: {result.UnwrapErr().Message}");
            Context.Stop(Self);
            return;
        }

        _ = SendVerificationSms(_verificationSessionQueryRecord.Mobile, _verificationSessionQueryRecord.Code,
            _verificationSessionQueryRecord.ExpiresAt);
        Context.System.Log.Info("Transitioning to Running state (new session created)");
        Become(Running);
        Self.Tell(new StartTimer());
    }

    private void Running()
    {
        Context.System.Log.Info("Entered Running state");
        Receive<StartTimer>(_ =>
        {
            Context.System.Log.Info("Processing StartTimer message");
            StartTimer();
        });
        Receive<TimerTick>(HandleTimerTick);
        Receive<VerifyCodeRcpMsg>(HandleVerifyCodeRcpMsg);
        Receive<PostponeSession>(HandlePostponeSession);
        Receive<StopTimer>(_ => _timerCancelable.Cancel());
    }

    private void HandleTimerTick(TimerTick tick)
    {
        if (tick.RemainingSeconds == 0)
        {
            Context.System.Log.Info(
                $"Session expired for device_id: {_verificationSessionQueryRecord.AppDeviceUniqueRec}");
            Context.Stop(Self);
        }
        else
        {
            _writer.WriteAsync(tick);
        }
    }

    private void StartTimer()
    {
        _timerCancelable = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
            initialDelay: TimeSpan.Zero,
            interval: _timerInterval,
            receiver: Self,
            message: new TimerTick
            {
                RemainingSeconds = CalculateRemainingSeconds(_verificationSessionQueryRecord.ExpiresAt),
                StreamId = Helpers.GuidToByteString(_streamId)
            },
            sender: ActorRefs.NoSender);
        Context.System.Log.Info("Timer started");
    }

    private async Task SendVerificationSms(string mobile, string code, DateTime expiresAt)
    {
        string message =
            $"Your verification code is: {code}. It will expire in {CalculateRemainingSeconds(expiresAt)} seconds.";
        await _snsProvider.SendSMSAsync(mobile, message);
    }

    private static string GenerateVerificationCode() => new Random().Next(10000, 99999).ToString();

    private static ulong CalculateRemainingSeconds(DateTime expiresAt)
    {
        TimeSpan remaining = expiresAt - DateTime.UtcNow;
        return (ulong)Math.Max(0, remaining.TotalSeconds);
    }

    protected override void PostStop()
    {
        _timerCancelable?.Cancel();
    }

    // Placeholder handlers
    private void HandleVerifyCodeRcpMsg(VerifyCodeRcpMsg msg)
    {
    }

    private void HandlePostponeSession(PostponeSession msg)
    {
    }
}