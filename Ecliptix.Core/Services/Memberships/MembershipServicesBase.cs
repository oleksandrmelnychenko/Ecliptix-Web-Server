using System.Globalization;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Domain.Memberships.WorkerActors;

namespace Ecliptix.Core.Services.Memberships;

public abstract class MembershipServicesBase(
    IActorRegistry actorRegistry) : Protobuf.Membership.MembershipServices.MembershipServicesBase
{
    protected readonly IActorRef MembershipActor = actorRegistry.Get<MembershipActor>();
    protected readonly IActorRef ProtocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();
    protected string CultureName { get; private set; } = CultureInfo.CurrentCulture.Name;
}