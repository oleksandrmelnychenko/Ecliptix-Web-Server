using System.Threading.Channels;
using Akka.Actor;
using Akka.Event;
using Ecliptix.Domain.Persistors;
using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Verification;

namespace Ecliptix.Domain.Memberships;

public record StartTimer;

public record StopTimer(uint ConnectId);

public class VerificationSessionActor : ReceiveActor
{
    private readonly ChannelWriter<TimerTick> _writer;
    private readonly IActorRef _persistor;
    private readonly SNSProvider _snsProvider;
    private readonly VerificationSessionQueryRecord _verificationSessionQueryRecord;
    private ICancelable? _timerCancelable;
    private readonly TimeSpan _sessionTimeout = TimeSpan.FromSeconds(60);
    private readonly TimeSpan _timerInterval = TimeSpan.FromSeconds(1);
    private readonly Guid _streamId = Guid.NewGuid();
    private readonly ILoggingAdapter _log = Context.GetLogger();
    private int _remainingSeconds;

    public VerificationSessionActor(
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
            Status = VerificationSessionStatus.Pending
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
            new VerificationSessionActor(connectId, streamId, mobile, deviceId, writer, persistor,
                snsProvider));

    private void Initializing()
    {
        _log.Info("Entering Initializing state");

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
        ReceiveAny(msg => _log.Warning($"Unexpected message: {msg.GetType()}"));

        _log.Info("Requesting existing verification session");
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
            _log.Info("Existing session found, sending SMS and transitioning to Running state");
            SendVerificationSms(existingSession.Mobile, existingSession.Code, existingSession.ExpiresAt)
                .ContinueWith(t =>
                {
                    if (t.IsFaulted)
                    {
                        _log.Error(t.Exception, "Failed to send SMS for existing session");
                    }
                    else
                    {
                        _log.Info("SMS sent successfully for existing session");
                    }
                    return new StartTimer();
                })
                .PipeTo(Self);
            Become(Running);
        }
        else
        {
            _log.Info("No valid session found, transitioning to CreatingSession state");
            Become(CreatingSession);
            _persistor.Ask<Result<Unit, ShieldFailure>>(
                    new CreateVerificationSessionRecordCommand(_verificationSessionQueryRecord))
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
            _log.Error($"Failed to create verification session: {result.UnwrapErr().Message}");
            Context.Stop(Self);
            return;
        }

        _log.Info("Session created, sending SMS and transitioning to Running state");
        SendVerificationSms(_verificationSessionQueryRecord.Mobile, _verificationSessionQueryRecord.Code,
                _verificationSessionQueryRecord.ExpiresAt)
            .ContinueWith(t =>
            {
                if (t.IsFaulted)
                {
                    _log.Error(t.Exception, "Failed to send SMS for new session");
                }
                else
                {
                    _log.Info("SMS sent successfully for new session");
                }
                return new StartTimer();
            })
            .PipeTo(Self);
        Become(Running);
    }

    private void Running()
    {
        _log.Info("Entered Running state");
        Receive<StartTimer>(_ =>
        {
            _log.Info("Processing StartTimer message");
            StartTimer();
        });
        ReceiveAsync<TimerTick>(HandleTimerTick);
        Receive<VerifyCodeCommand>(HandleVerifyCode);
        Receive<PostponeSession>(HandlePostponeSession);
        Receive<StopTimer>(_ => _timerCancelable?.Cancel());
    }

    private async Task HandleTimerTick(TimerTick _)
    {
        _log.Info($"Timer tick: {_remainingSeconds:D2}:{_remainingSeconds % 60:D2} remaining");

        if (_remainingSeconds <= 0)
        {
            _log.Info($"Session expired for device_id: {_verificationSessionQueryRecord.AppDeviceUniqueRec}");
            _persistor.Tell(new UpdateSessionStatusCommand(
                _verificationSessionQueryRecord.AppDeviceUniqueRec, VerificationSessionStatus.Expired));
            _timerCancelable?.Cancel();
            Context.Stop(Self);
        }
        else
        {
            await _writer.WriteAsync(new TimerTick
            {
                RemainingSeconds = (ulong)_remainingSeconds,
                StreamId = Helpers.GuidToByteString(_streamId)
            });
            _remainingSeconds--;
        }
    }

    private void StartTimer()
    {
        _remainingSeconds = (int)_sessionTimeout.TotalSeconds;
        _timerCancelable = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
            initialDelay: TimeSpan.Zero,
            interval: _timerInterval,
            receiver: Self,
            message: new TimerTick(),
            sender: ActorRefs.NoSender);
        _log.Info("Timer started");
    }

    private async Task SendVerificationSms(string mobile, string code, DateTime expiresAt)
    {
        string message =
            $"Your verification code is: {code}. It will expire in {CalculateRemainingSeconds(expiresAt)} seconds.";
        try
        {
            await _snsProvider.SendSMSAsync(mobile, message);
            _log.Info("SMS sent successfully");
        }
        catch (Exception ex)
        {
            _log.Error(ex, "Failed to send SMS");
            throw;
        }
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

    private void HandleVerifyCode(VerifyCodeCommand command)
    {
       _persistor.Forward(command);
    }

    private void HandlePostponeSession(PostponeSession msg)
    {
        // Placeholder for future implementation
    }
}