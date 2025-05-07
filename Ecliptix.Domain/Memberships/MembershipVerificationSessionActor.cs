using System.Threading.Channels;
using Akka.Actor;
using Akka.Event;
using Ecliptix.Domain.Persistors;
using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Verification;

namespace Ecliptix.Domain.Memberships;

public record StartTimer;

public class MembershipVerificationSessionActor : ReceiveActor
{
    private readonly ChannelWriter<TimerTick> _writer;

    private readonly IActorRef _persistor;

    private readonly SNSProvider _snsProvider;

    private readonly VerificationSessionQueryRecord _verificationSessionQueryRecord;

    private const int SessionTimeout = 60;
    private const int TimerIntervalSecs = 1;

    private CancellationTokenSource _timerCancellationTokenSource;

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
        _timerCancellationTokenSource = new CancellationTokenSource();

        _verificationSessionQueryRecord =
            new VerificationSessionQueryRecord(connectId, streamId, mobile, uniqueRec, GenerateVerificationCode())
            {
                ExpiresAt = DateTime.UtcNow.AddSeconds(SessionTimeout),
                Status = MembershipVerificationSessionStatus.Pending
            };

        //ReceiveAsync<StartVerificationSessionStreamCommand>(HandleStartVerificationSessionStreamCommand);
        ReceiveAsync<TimerTick>(HandleTimerTick);
        ReceiveAsync<VerifyCodeRcpMsg>(HandleVerifyCodeRcpMsg);
        ReceiveAsync<PostponeSession>(HandlePostponeSession);
        ReceiveAsync<StopTimer>(HandleStopTimer);
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

    protected override void PreStart()
    {
        // Check for an existing pending session
        Task<Result<VerificationSessionQueryRecord?, ShieldFailure>> existingSessionTask =
            GetVerificationSessionQueryRecordIfExist();
        existingSessionTask.Wait(); // Synchronous wait in PreStart to ensure session check completes

        Result<VerificationSessionQueryRecord?, ShieldFailure> existingSessionResult = existingSessionTask.Result;
        if (existingSessionResult.IsErr)
        {
            Context.System.Log.Error(
                $"Failed to check for existing session: {existingSessionResult.UnwrapErr().Message}");
            Context.Stop(Self);
            return;
        }

        VerificationSessionQueryRecord? existingSession = existingSessionResult.Unwrap();
        if (existingSession != null && existingSession.ExpiresAt > DateTime.UtcNow)
        {
            Task smsTask = SendVerificationSms(_verificationSessionQueryRecord.Mobile,
                _verificationSessionQueryRecord.Code,
                _verificationSessionQueryRecord.ExpiresAt);
            smsTask.Wait();

            if (smsTask.Exception != null)
            {
                Context.System.Log.Warning($"Failed to resend verification SMS: {smsTask.Exception.Message}");
            }
        }
        else
        {
            Task<Result<bool, ShieldFailure>> createSessionTask = CreateMembershipVerificationSessionRecord();
            createSessionTask.Wait();

            Result<bool, ShieldFailure> createSessionResult = createSessionTask.Result;
            if (createSessionResult.IsErr)
            {
                Context.System.Log.Error(
                    $"Failed to create verification session: {createSessionResult.UnwrapErr().Message}");
                Context.Stop(Self);
                return;
            }

            Task smsTask = SendVerificationSms(_verificationSessionQueryRecord.Mobile,
                _verificationSessionQueryRecord.Code,
                _verificationSessionQueryRecord.ExpiresAt);
            smsTask.Wait();

            if (smsTask.Exception != null)
            {
                Context.System.Log.Warning($"Failed to send verification SMS: {smsTask.Exception.Message}");
            }
        }

        Task timerTask = Task.Run(async () =>
        {
            for (int i = 0; i < SessionTimeout; i++)
            {
                await Task.Delay(1000);
                await _writer.WriteAsync(new TimerTick());
            }
        });

        if (timerTask.IsFaulted)
        {
            Context.System.Log.Warning($"Failed to start session timer: {timerTask.Exception?.Message}");
        }
    }

    private async Task HandleStartTimer(StartTimer _)
    {
        Task timerTask = Task.Run(async () =>
        {
            CancellationToken cancellationToken = _timerCancellationTokenSource.Token;
            Guid deviceId = _verificationSessionQueryRecord.AppDeviceUniqueRec;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(TimerIntervalSecs), cancellationToken);
                    DateTime now = DateTime.UtcNow;
                    ulong remainingSeconds =
                        (ulong)Math.Max(0, (_verificationSessionQueryRecord.ExpiresAt - now).TotalSeconds);

                    if (remainingSeconds == 0)
                    {
                        Context.System.Log.Info($"Session expired for device_id: {deviceId}");
                        Context.Stop(Self);
                        break;
                    }

                    await _writer.WriteAsync(new TimerTick
                    {
                        RemainingSeconds = remainingSeconds
                    }, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Context.System.Log.Warning(
                        $"Failed to send TimerTick for device_id: {deviceId}, error: {ex.Message}");
                }
            }
        });

        if (timerTask.IsFaulted)
        {
            Context.System.Log.Warning($"Failed to start session timer: {timerTask.Exception?.Message}");
        }
    }

    private async Task HandleStopTimer(StopTimer msg)
    {
        await _timerCancellationTokenSource.CancelAsync()!;
        _timerCancellationTokenSource.Dispose();
        _timerCancellationTokenSource = new CancellationTokenSource();
    }

    protected override void PostStop()
    {
        _timerCancellationTokenSource?.Cancel();
        _timerCancellationTokenSource?.Dispose();
    }

    private async Task HandleTimerTick(TimerTick _)
    {
    }

    private async Task HandleVerifyCodeRcpMsg(VerifyCodeRcpMsg msg)
    {
    }

    private async Task HandlePostponeSession(PostponeSession msg)
    {
    }

    private async Task HandleCheckSessionStatus(CheckVerificationSessionStatusCommand msg)
    {
    }

    private async Task<Result<bool, ShieldFailure>> CreateMembershipVerificationSessionRecord() =>
        await _persistor.Ask<Result<bool, ShieldFailure>>(
            new CreateMembershipVerificationSessionRecordCommand(_verificationSessionQueryRecord));

    private async Task<Result<VerificationSessionQueryRecord?, ShieldFailure>>
        GetVerificationSessionQueryRecordIfExist() =>
        await _persistor.Ask<Result<VerificationSessionQueryRecord?, ShieldFailure>>(
            new GetVerificationSessionCommand(_verificationSessionQueryRecord.AppDeviceUniqueRec));

    private async Task UpdateSessionStatus(string status)
    {
    }

    private async Task SendVerificationSms(string mobile, string code, DateTime expiresAt)
    {
        string message =
            $"Your verification code is: {code}. It will expire in {CalculateRemainingSeconds(expiresAt)} seconds.";
        await _snsProvider.SendSMSAsync(mobile, message);
    }

    private static string GenerateVerificationCode() => new Random().Next(10000, 99999).ToString();

    private long CalculateRemainingSeconds(DateTime expiresAt)
    {
        if (expiresAt == DateTime.MinValue)
        {
            return 0;
        }

        return (long)Math.Max(0, (expiresAt - DateTime.UtcNow).TotalSeconds);
    }
}