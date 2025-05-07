using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Ecliptix.Protobuf.VerificationServices;
using Grpc.Core;

namespace Ecliptix.Core.Services.Memberships;

public class VerificationServiceBase(
    IActorRegistry actorRegistry,
    ILogger<VerificationServices> logger) : VerificationServiceActions.VerificationServiceActionsBase
{
    protected readonly ILogger<VerificationServices> Logger = logger;
    protected readonly IActorRef ProtocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();
    protected readonly IActorRef VerificationSessionManagerActor = actorRegistry.Get<VerificationSessionManagerActor>();

    protected async Task<Result<byte[], ShieldFailure>> DecryptRequest(CipherPayload request,ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], ShieldFailure> decryptResult = await ProtocolActor
            .Ask<Result<byte[], ShieldFailure>>(
                new DecryptCipherPayloadCommand(
                    connectId,
                    PubKeyExchangeType.AppDeviceEphemeralConnect,
                    request
                ),
                context.CancellationToken
            );

        return decryptResult;
    }
    
}