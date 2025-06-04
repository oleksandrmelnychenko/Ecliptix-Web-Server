using System.Collections.Concurrent;
using Akka.Actor;
using Ecliptix.Domain.Memberships.Events;
using Ecliptix.Domain.Persistors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Extensions.Localization;
using Ecliptix.Domain.Memberships.Failures;

namespace Ecliptix.Domain.Memberships;

public class VerificationFlowManagerActor : ReceiveActor
{
    private readonly IStringLocalizer<VerificationFlowManagerActor> _localizer;
    private readonly IActorRef _persistor;
    private readonly IActorRef _membershipActor;
    private readonly SNSProvider _snsProvider;

    private readonly ConcurrentDictionary<uint, IActorRef> _sessions = new();

    public VerificationFlowManagerActor(
        IActorRef persistor,
        IActorRef membershipActor,
        SNSProvider snsProvider,
        IStringLocalizer<VerificationFlowManagerActor> localizer)
    {
        _localizer = localizer;
        _persistor = persistor;
        _membershipActor = membershipActor;
        _snsProvider = snsProvider;

        Receive<VerifyFlowActorEvent>(HandleVerifyCode);
        Receive<InitiateVerificationFlowActorEvent>(HandleStartVerificationSession);
        Receive<EnsurePhoneNumberActorEvent>(cmd => _persistor.Forward(cmd));
        Receive<CloseVerificationFlowEvent>(HandleStopTimer);
        Receive<Terminated>(HandleTerminated);
    }

    private void HandleVerifyCode(VerifyFlowActorEvent actorEvent)
    {
        if (_sessions.TryGetValue(actorEvent.ConnectId, out IActorRef? existing))
        {
            existing.Forward(actorEvent);
        }
        else
        {
            //TODO NO ACTIVE SESSION, WE NEED TO WAIT FOR THE SESSION TO BE CREATED..
            
            Sender.Tell(Result<VerifyCodeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.NotFound("No active verification session found")));
        }
    }

    private void HandleStartVerificationSession(InitiateVerificationFlowActorEvent @event)
    {
        if (_sessions.TryGetValue(@event.ConnectId, out IActorRef? existing))
        {
            existing.Forward(@event);
        }
        else
        {
            if (@event.RequestType == InitiateVerificationRequest.Types.Type.SendOtp)
            {
                CreateVerificationSessionActor(@event);
                Sender.Tell(Result<bool, VerificationFlowFailure>.Ok(true));
            }
            else
            {
                Sender.Tell(Result<bool, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("No active session for resend request")));
            }
        }
    }

    private void HandleStopTimer(CloseVerificationFlowEvent msg)
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

    private void CreateVerificationSessionActor(InitiateVerificationFlowActorEvent @event)
    {
        IActorRef verificationSessionActorRef = Context.ActorOf(VerificationFlowActor.Build(
            @event.ConnectId,
            @event.PhoneNumberIdentifier,
            @event.AppDeviceIdentifier,
            @event.Purpose,
            @event.ChannelWriter,
            _persistor,
            _membershipActor,
            _snsProvider,
            _localizer
        ));

        _sessions[@event.ConnectId] = verificationSessionActorRef;
        Context.Watch(verificationSessionActorRef);
    }

    public static Props Build(IActorRef persistor, IActorRef membershipActor, SNSProvider snsProvider,
        IStringLocalizer<VerificationFlowManagerActor> localizer) =>
        Props.Create(() => new VerificationFlowManagerActor(persistor, membershipActor, snsProvider, localizer));
}