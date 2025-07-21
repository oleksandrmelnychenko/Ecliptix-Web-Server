using System.Globalization;
using Akka.Actor;
using Ecliptix.Core.Protocol;
using Ecliptix.Domain.Memberships.WorkerActors;

namespace Ecliptix.Core.Services.Memberships;

public abstract class MembershipServicesBase(
    IEcliptixActorRegistry actorRegistry,
    ICipherPayloadHandler cipherPayloadHandler
    ) : Protobuf.Membership.MembershipServices.MembershipServicesBase
{
    protected readonly IActorRef MembershipActor = actorRegistry.Get<MembershipActor>();
    protected readonly ICipherPayloadHandler CipherPayloadHandler = cipherPayloadHandler;
    protected string CultureName { get; private set; } = CultureInfo.CurrentCulture.Name;
}