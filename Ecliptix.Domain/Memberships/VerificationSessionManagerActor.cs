using System.Collections.Concurrent;
using Akka.Actor;
using Ecliptix.Domain.Persistors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Extensions.Localization;

namespace Ecliptix.Domain.Memberships;

public class VerificationSessionManagerActor : ReceiveActor
{
    private readonly IStringLocalizer<VerificationSessionManagerActor> _localizer;
    private readonly IActorRef _persistor;
    private readonly IActorRef _membershipActor;
    private readonly SNSProvider _snsProvider;

    private readonly ConcurrentDictionary<uint, IActorRef> _sessions = new();

    public VerificationSessionManagerActor(
        IActorRef persistor,
        IActorRef membershipActor,
        SNSProvider snsProvider,
        IStringLocalizer<VerificationSessionManagerActor> localizer)
    {
        _localizer = localizer;
        _persistor = persistor;
        _membershipActor = membershipActor;
        _snsProvider = snsProvider;

        Receive<VerifyCodeActorCommand>(HandleVerifyCode);
        Receive<InitiateVerificationActorCommand>(HandleStartVerificationSession);
        Receive<EnsurePhoneNumberActorCommand>(cmd => _persistor.Forward(cmd));
        Receive<StopTimer>(HandleStopTimer);
        Receive<Terminated>(HandleTerminated);
    }

    private void HandleVerifyCode(VerifyCodeActorCommand actorCommand)
    {
        if (_sessions.TryGetValue(actorCommand.ConnectId, out IActorRef? existing))
        {
            existing.Forward(actorCommand);
        }
        else
        {
            //TODO NO ACTIVE SESSION, WE NEED TO WAIT FOR THE SESSION TO BE CREATED..
            
            Sender.Tell(Result<VerifyCodeResponse, ShieldFailure>.Err(
                ShieldFailure.Generic("No active session")));
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
            if (command.RequestType == InitiateVerificationRequest.Types.Type.SendOtp)
            {
                CreateVerificationSessionActor(command);
                Sender.Tell(Result<bool, ShieldFailure>.Ok(true));
            }
            else
            {
                Sender.Tell(Result<bool, ShieldFailure>.Err(
                    ShieldFailure.Generic("No active session for resend")));
            }
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

    private void CreateVerificationSessionActor(InitiateVerificationActorCommand command)
    {
        IActorRef verificationSessionActorRef = Context.ActorOf(VerificationSessionActor.Build(
            command.ConnectId,
            command.PhoneNumberIdentifier,
            command.SystemDeviceIdentifier,
            command.Purpose,
            command.Writer,
            _persistor,
            _membershipActor,
            _snsProvider,
            _localizer
        ));

        _sessions[command.ConnectId] = verificationSessionActorRef;

        Context.Watch(verificationSessionActorRef);
    }

    public static Props Build(IActorRef persistor, IActorRef membershipActor, SNSProvider snsProvider,
        IStringLocalizer<VerificationSessionManagerActor> localizer) =>
        Props.Create(() => new VerificationSessionManagerActor(persistor, membershipActor, snsProvider, localizer));
}