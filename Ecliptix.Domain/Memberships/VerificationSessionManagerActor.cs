using System.Collections.Concurrent;
using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.Protobuf.Authentication;

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

        Receive<VerifyCodeActorCommand>(HandleVerifyCode);
        Receive<InitiateVerificationActorCommand>(HandleStartVerificationSession);
        Receive<StopTimer>(HandleStopTimer);
        Receive<Terminated>(HandleTerminated);
    }

    private void HandleVerifyCode(VerifyCodeActorCommand actorCommand)
    {
        if (_sessions.TryGetValue(actorCommand.ConnectId, out IActorRef? existing))
        {
            existing.Forward(actorCommand);
        }
    }

    private void HandleStartVerificationSession(InitiateVerificationActorCommand command)
    {
        if (_sessions.TryGetValue(command.ConnectId, out IActorRef? existing))
        {
            existing.Forward(command);
        }
        else
        {
            CreateMembershipVerificationSessionActor(command);
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

    private void CreateMembershipVerificationSessionActor(InitiateVerificationActorCommand msg)
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

public record InitiateVerificationActorCommand(
    uint ConnectId,
    string Mobile,
    Guid DeviceId,
    ChannelWriter<VerificationCountdownUpdate> Writer);

public record VerifyCodeActorCommand(uint ConnectId, string Code, VerificationPurpose VerificationPurpose);