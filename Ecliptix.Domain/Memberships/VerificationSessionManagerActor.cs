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

        Receive<VerifyCodeCommand>(HandleVerifyCode);
        Receive<StartVerificationSessionStreamCommand>(HandleStartVerificationSession);
        Receive<PostponeSession>(HandlePostponeSession);
        Receive<StopTimer>(HandleStopTimer);
        Receive<Terminated>(HandleTerminated);
    }

    private void HandleVerifyCode(VerifyCodeCommand command)
    {
        if (_sessions.TryGetValue(command.ConnectId, out IActorRef? existing))
        {
            existing.Forward(command);
        }
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

    private void HandlePostponeSession(PostponeSession msg)
    {
        if (_sessions.TryGetValue(msg.ConnectId, out IActorRef? actor))
        {
            actor.Tell(msg);
        }
    }

    private void HandleStopTimer(StopTimer msg)
    {
        if (_sessions.TryGetValue(msg.ConnectId, out IActorRef? actor))
        {
            actor.Tell(msg);
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

    private void CreateMembershipVerificationSessionActor(StartVerificationSessionStreamCommand msg)
    {
        IActorRef? actor = Context.ActorOf(VerificationSessionActor.Build(
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
    }

    public static Props Build(IActorRef persistor, SNSProvider snsProvider) =>
        Props.Create(() => new VerificationSessionManagerActor(persistor, snsProvider));
}

public record StartVerificationSessionStreamCommand(
    uint ConnectId,
    string Mobile,
    Guid DeviceId,
    ChannelWriter<TimerTick> Writer);

public record PostponeSession(uint ConnectId);

public record CheckVerificationSessionStatusCommand(StartVerificationSessionStreamCommand Request);

public record UpdateSessionExpiresAt(uint UniqueId, DateTime ExpiresAt);

public record VerifyCodeCommand(uint ConnectId, string Code,VerificationType VerificationType);