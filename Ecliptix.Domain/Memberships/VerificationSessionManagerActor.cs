using System.Collections.Concurrent;
using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.Verification;

namespace Ecliptix.Domain.Memberships;

public class VerificationSessionManagerActor : ReceiveActor
{
    private readonly IActorRef _persistor;

    private readonly SNSProvider _snsProvider;

    private readonly ConcurrentDictionary<uint, IActorRef> _sessions = new();

    public VerificationSessionManagerActor(
        IActorRef persistor,
        SNSProvider snsProvider
    )
    {
        _persistor = persistor;
        _snsProvider = snsProvider;

        Receive<StartVerificationSessionStreamCommand>(HandleStartVerificationSession);
        Receive<VerifyCodeRcpMsg>(HandleVerifyCodeRcpMsg);
        Receive<PostponeSession>(HandlePostponeSession);
        Receive<StopTimer>(HandleStopTimer);
        Receive<Terminated>(HandleTerminated);
    }

    private void HandleStartVerificationSession(StartVerificationSessionStreamCommand command)
    {
        if (_sessions.TryGetValue(command.ConnectId, out IActorRef? existing))
        {
            existing.Tell(new CheckVerificationSessionStatusCommand(command));
        }
        else
        {
            CreateMembershipVerificationSessionActor(command);
        }
    }

    private void HandleVerifyCodeRcpMsg(VerifyCodeRcpMsg msg)
    {
        uint deviceId = BitConverter.ToUInt32(msg.ConnectId, 0);
        if (_sessions.TryGetValue(deviceId, out IActorRef? actor))
        {
            actor.Forward(msg);
        }
        else
        {
            //Sender.Tell(Result.Ok(new CipherPayload { Status = (int)StatusCode.NotFound }));
        }
    }

    private void HandlePostponeSession(PostponeSession msg)
    {
        if (_sessions.TryGetValue(msg.ConnectId, out var actor))
        {
            actor.Tell(msg);
        }
        else
        {
        }
    }

    private void HandleStopTimer(StopTimer msg)
    {
        if (_sessions.TryGetValue(msg.ConnectId, out var actor))
        {
            actor.Tell(msg);
        }
        else
        {
        }
    }

    private void HandleTerminated(Terminated msg)
    {
        foreach (KeyValuePair<uint, IActorRef> entry in _sessions)
        {
            if (entry.Value.Equals(msg.ActorRef))
            {
                _sessions.TryRemove(entry.Key, out _);
                break;
            }
        }
    }

    private IActorRef CreateMembershipVerificationSessionActor(StartVerificationSessionStreamCommand msg)
    {
        IActorRef? actor = Context.ActorOf(MembershipVerificationSessionActor.Build(
            msg.ConnectId,
            Guid.NewGuid(),
            msg.Mobile,
            msg.DeviceId,
            msg.Writer,
            _persistor,
            _snsProvider
        ));
        
        _sessions[msg.ConnectId] = actor;
        Context.Watch(actor);

        return actor;
    }

    public static Props Build(IActorRef persistor, SNSProvider snsProvider) =>
        Props.Create(() => new VerificationSessionManagerActor(persistor, snsProvider));
}

public record StartVerificationSessionStreamCommand(
    uint ConnectId,
    string Mobile,
    Guid DeviceId,
    ChannelWriter<TimerTick> Writer);

public record VerifyCodeRcpMsg(CipherPayload InboundCipher, byte[] ConnectId);

public record PostponeSession(uint ConnectId);

public record StopTimer(uint ConnectId);

public record CheckVerificationSessionStatusCommand(StartVerificationSessionStreamCommand Request);

public record UpdateSessionExpiresAt(uint UniqueId, DateTime ExpiresAt);