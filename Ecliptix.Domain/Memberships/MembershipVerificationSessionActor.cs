using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.Domain.Persistors;
using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Verification;

namespace Ecliptix.Domain.Memberships;

public class MembershipVerificationSessionActor : ReceiveActor
{
    private readonly ChannelWriter<TimerTick> _writer;
    
    private readonly IActorRef _persistor;
    
    private readonly SNSProvider _snsProvider;
    
    private readonly VerificationSessionQueryRecord _verificationSessionQueryRecord;

    private const int SessionTimeout = 60;

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

        _verificationSessionQueryRecord =
            new VerificationSessionQueryRecord(connectId, streamId, mobile, uniqueRec, GenerateVerificationCode())
            {
                ExpiresAt = DateTime.UtcNow.AddSeconds(SessionTimeout),
                Status = MembershipVerificationSessionStatus.Pending
            };

        ReceiveAsync<StartVerificationSessionStreamCommand>(HandleStartVerificationSessionStreamCommand);
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
        _ = SendVerificationSms(_verificationSessionQueryRecord.Mobile, _verificationSessionQueryRecord.Code,
            _verificationSessionQueryRecord.ExpiresAt);
        _ = SaveSession();
    }

    protected override void PostStop()
    {
    }

    private async Task HandleStartVerificationSessionStreamCommand(StartVerificationSessionStreamCommand _)
    {
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

    private async Task HandleStopTimer(StopTimer msg)
    {
    }

    private async Task HandleCheckSessionStatus(CheckVerificationSessionStatusCommand msg)
    {
    }

    private async Task SaveSession()
    {
        _ = _persistor.Ask<Result<bool, ShieldFailure>>(
            new CreateMembershipVerificationSessionRecordCommand(_verificationSessionQueryRecord));
    }

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