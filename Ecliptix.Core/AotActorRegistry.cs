using System.Collections.Concurrent;
using Akka.Actor;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Domain.AppDevices.Persistors;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Memberships.WorkerActors;

namespace Ecliptix.Core;

public sealed class AotActorRegistry : IEcliptixActorRegistry
{
    private readonly ConcurrentDictionary<int, IActorRef> _actors = new();

    public void Register(int actorId, IActorRef actorRef)
    {
        _actors[actorId] = actorRef;
    }

    public IActorRef Get(int actorId)
    {
        return _actors.TryGetValue(actorId, out IActorRef? actorRef)
            ? actorRef
            : throw new InvalidOperationException(
                $"Actor with ID {actorId} ({ActorTypeMap.GetActorName(actorId)}) not registered.");
    }

    public void Register<TActor>(IActorRef actorRef) where TActor : ActorBase
    {
        int actorId = GetActorIdForType<TActor>();
        Register(actorId, actorRef);
    }

    public IActorRef Get<TActor>() where TActor : ActorBase
    {
        int actorId = GetActorIdForType<TActor>();
        return Get(actorId);
    }

    private static int GetActorIdForType<TActor>() where TActor : ActorBase
    {
        return typeof(TActor).Name switch
        {
            nameof(EcliptixProtocolSystemActor) => ActorIds.EcliptixProtocolSystemActor,
            nameof(AppDevicePersistorActor) => ActorIds.AppDevicePersistorActor,
            nameof(VerificationFlowPersistorActor) => ActorIds.VerificationFlowPersistorActor,
            nameof(VerificationFlowManagerActor) => ActorIds.VerificationFlowManagerActor,
            nameof(MembershipPersistorActor) => ActorIds.MembershipPersistorActor,
            nameof(MembershipActor) => ActorIds.MembershipActor,
            _ => throw new ArgumentException($"Unknown actor type: {typeof(TActor).Name}")
        };
    }
}