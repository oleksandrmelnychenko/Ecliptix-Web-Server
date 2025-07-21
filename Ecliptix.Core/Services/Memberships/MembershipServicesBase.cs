using System.Globalization;
using Akka.Actor;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Domain.Memberships.WorkerActors;

namespace Ecliptix.Core.Services.Memberships;

public abstract class MembershipServicesBase(
    IEcliptixActorRegistry actorRegistry) : Protobuf.Membership.MembershipServices.MembershipServicesBase
{
    protected readonly IActorRef MembershipActor = actorRegistry.Get<MembershipActor>();
    protected readonly ICipherPayloadHandler CipherPayloadHandler =
        new CipherPayloadHandler(actorRegistry.Get<EcliptixProtocolSystemActor>());
    protected string CultureName { get; private set; } = CultureInfo.CurrentCulture.Name;
}