using System.Globalization;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Grpc.Core;

namespace Ecliptix.Core.Services.Memberships;

public abstract class AuthVerificationServicesBase(
    IActorRegistry actorRegistry,
    ILogger<AuthVerificationServices> logger)
    : Protobuf.Membership.AuthVerificationServices.AuthVerificationServicesBase
{
    private readonly IActorRef _protocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();
    protected readonly ILogger<AuthVerificationServices> Logger = logger;

    protected readonly IActorRef VerificationFlowManagerActor = actorRegistry.Get<VerificationFlowManagerActor>();

    protected string CultureName { get; private set; } = CultureInfo.CurrentCulture.Name;

    protected void StopVerificationFlowActor(ServerCallContext context, uint connectId)
    {
        try
        {
            ActorSystem actorSystem = context.GetHttpContext().RequestServices.GetRequiredService<ActorSystem>();

            string actorName = $"flow-{connectId}";
            string actorPath = $"/user/{nameof(VerificationFlowManagerActor)}/{actorName}";

            ActorSelection? actorSelection = actorSystem.ActorSelection(actorPath);

            actorSelection.Tell(PoisonPill.Instance);

            Logger.LogInformation(
                "Client for ConnectId {ConnectId} disconnected. Sent PoisonPill to actor selection [{ActorPath}]",
                connectId, actorPath);
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex,
                "Failed to send stop signal to verification flow actor for ConnectId {ConnectId}",
                connectId);
        }
    }

    protected async Task<Result<byte[], EcliptixProtocolFailure>> DecryptRequest(CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], EcliptixProtocolFailure> decryptResult = await _protocolActor
            .Ask<Result<byte[], EcliptixProtocolFailure>>(
                new DecryptCipherPayloadActorActorEvent(
                    connectId,
                    PubKeyExchangeType.DataCenterEphemeralConnect,
                    request
                ),
                context.CancellationToken
            );

        return decryptResult;
    }

    protected async Task<Result<CipherPayload, EcliptixProtocolFailure>> EncryptRequest(byte[] payload,
        PubKeyExchangeType pubKeyExchangeType, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<CipherPayload, EcliptixProtocolFailure> encryptResult = await _protocolActor
            .Ask<Result<CipherPayload, EcliptixProtocolFailure>>(
                new EncryptPayloadActorCommand(
                    connectId,
                    pubKeyExchangeType,
                    payload
                ),
                context.CancellationToken
            );

        return encryptResult;
    }
}