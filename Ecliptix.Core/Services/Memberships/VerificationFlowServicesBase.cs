using System.Globalization;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Protobuf.Membership;
using Grpc.Core;
using Serilog;

namespace Ecliptix.Core.Services.Memberships;

public abstract class VerificationFlowServicesBase(
    IEcliptixActorRegistry actorRegistry)
    : AuthVerificationServices.AuthVerificationServicesBase
{
    protected readonly IActorRef ProtocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();

    protected readonly IActorRef VerificationFlowManagerActor = actorRegistry.Get<VerificationFlowManagerActor>();

    protected string CultureName { get; private set; } = CultureInfo.CurrentCulture.Name;

    protected void StopVerificationFlowActor(ServerCallContext context, uint connectId)
    {
        try
        {
            ActorSystem actorSystem = context.GetHttpContext().RequestServices.GetRequiredService<ActorSystem>();

            string actorName = $"flow-{connectId}";
            string actorPath = $"/membership/{nameof(VerificationFlowManagerActor)}/{actorName}";

            ActorSelection? actorSelection = actorSystem.ActorSelection(actorPath);

            actorSelection.Tell(PoisonPill.Instance);

            Log.Information(
                "Client for ConnectId {ConnectId} disconnected. Sent PoisonPill to actor selection [{ActorPath}]",
                connectId, actorPath);
        }
        catch (Exception ex)
        {
            Log.Warning(ex,
                "Failed to send stop signal to verification flow actor for ConnectId {ConnectId}",
                connectId);
        }
    }
}